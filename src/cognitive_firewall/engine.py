"""Shared admission controller used by all adapters."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cognitive_firewall.detectors.injection import detect_injection
from cognitive_firewall.detectors.pii import detect_pii
from cognitive_firewall.detectors.secrets import detect_secrets
from cognitive_firewall.policy.evaluator import evaluate_policy
from cognitive_firewall.policy.models import PolicyBundle, PolicyOutcome
from cognitive_firewall.risk import score_findings
from cognitive_firewall.schemas import (
    DecisionAction,
    EvaluationRequest,
    EvaluationResponse,
    Finding,
    Operation,
    Provenance,
)
from cognitive_firewall.storage.approvals import ApprovalBinding
from cognitive_firewall.storage.audit import AuditEvent
from cognitive_firewall.storage.memory import MemoryRecord
from cognitive_firewall.transforms.redaction import transform_payload
from cognitive_firewall.transforms.verification import verify_transformation

_PII_TRANSFORMS = {
    "email": "pseudonymize",
    "username": "pseudonymize",
    "customer_id": "pseudonymize",
    "phone": "redact",
    "ip": "redact",
}
_SENSITIVE_SCHEMA_FIELDS = {
    "email",
    "emailaddress",
    "phone",
    "phonenumber",
    "mobile",
    "mobilephone",
    "telephone",
    "ip",
    "ipaddress",
    "username",
    "handle",
    "customerid",
    "customernumber",
    "accountid",
    "accountnumber",
    "apikey",
    "accesstoken",
    "secret",
    "password",
    "privatekey",
}


class Evaluator:
    def __init__(
        self,
        policy: PolicyBundle | None,
        audit_store: Any,
        mapping_store: Any,
        memory_store: Any | None = None,
        approval_store: Any | None = None,
        trusted_system_hashes: dict[str, str] | None = None,
        policy_store: Any | None = None,
    ):
        self.policy = policy
        self.audit_store = audit_store
        self.mapping_store = mapping_store
        self.memory_store = memory_store
        self.approval_store = approval_store
        self.trusted_system_hashes = trusted_system_hashes or {}
        self.policy_store = policy_store

    def _closed(self, reason: str) -> EvaluationResponse:
        return EvaluationResponse(
            decision=DecisionAction.BLOCK,
            safe_payload=None,
            findings=[],
            reason_codes=[reason],
            injection_score=0,
            privacy_score=0,
            policy_hash=self.policy.policy_hash if self.policy else "",
            audit_id="",
        )

    @staticmethod
    def _has_unsafe_key(value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if (
                    detect_pii(key)
                    or detect_secrets(key)
                    or detect_injection(key, source="object_key")
                    or (
                        re.sub(r"[^a-z0-9]", "", key.lower()) in _SENSITIVE_SCHEMA_FIELDS
                        and child is not None
                        and not isinstance(child, str)
                    )
                    or Evaluator._has_unsafe_key(child)
                ):
                    return True
        elif isinstance(value, list):
            return any(Evaluator._has_unsafe_key(item) for item in value)
        return False

    @staticmethod
    def _minimum_outcome(
        outcome: PolicyOutcome, findings: list[Finding], operation: Operation
    ) -> PolicyOutcome:
        categories = {finding.category for finding in findings}
        if "secret" in categories:
            return PolicyOutcome(action=DecisionAction.BLOCK, reason_codes=["secret_floor"])
        if any(f.category == "injection" and f.severity >= 80 for f in findings):
            return PolicyOutcome(action=DecisionAction.BLOCK, reason_codes=["injection_floor"])
        if outcome.action in {DecisionAction.BLOCK, DecisionAction.REQUIRE_APPROVAL}:
            return outcome
        required = {
            category: (
                "redact" if operation in {Operation.EXPORT, Operation.MODEL_OUTPUT} else action
            )
            for category, action in _PII_TRANSFORMS.items()
            if category in categories
        }
        if not required:
            return outcome
        transformations = dict(outcome.transformations)
        for category, minimum in required.items():
            if minimum == "redact" or transformations.get(category) != "redact":
                transformations[category] = minimum
        return outcome.model_copy(
            update={
                "action": DecisionAction.SANITIZE,
                "transformations": transformations,
                "reason_codes": outcome.reason_codes + ["privacy_floor"],
            }
        )

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        try:
            policy = self.policy_store.active_bundle() if self.policy_store else self.policy
            if policy is None:
                return self._closed("policy_unavailable")
            source_id = request.provenance.source_id if request.provenance else ""
            system_digest = (
                hashlib.sha256(request.payload.encode("utf-8")).hexdigest()
                if isinstance(request.payload, str)
                else ""
            )
            trusted_system = (
                request.source == "system"
                and self.trusted_system_hashes.get(source_id) == system_digest
                and bool(system_digest)
            )
            effective_request = request.model_copy(
                update={
                    "provenance": Provenance(
                        source_id=source_id,
                        trust_level="trusted" if trusted_system else "untrusted",
                    )
                }
            )
            findings = (
                [] if trusted_system else detect_injection(request.payload, source=request.source)
            )
            if request.source == "system" and not trusted_system:
                findings.append(
                    Finding(
                        category="injection",
                        severity=100,
                        reason_code="system_prompt_unrecognized",
                        detector="provenance",
                    )
                )
            findings += detect_pii(request.payload)
            findings += detect_secrets(request.payload)
            unsafe_key = self._has_unsafe_key(request.payload)
            if unsafe_key:
                findings.append(
                    Finding(
                        category="secret",
                        severity=100,
                        reason_code="unsafe_object_key",
                        detector="object_key",
                    )
                )
            injection_score, privacy_score = score_findings(findings)
            outcome = evaluate_policy(effective_request, findings, policy)
            if unsafe_key:
                outcome = PolicyOutcome(
                    action=DecisionAction.BLOCK, reason_codes=["unsafe_object_key"]
                )
            else:
                outcome = self._minimum_outcome(outcome, findings, request.operation)

            approval_id = None
            if request.approval_id and not unsafe_key:
                if outcome.action != DecisionAction.REQUIRE_APPROVAL or self.approval_store is None:
                    return self._closed("approval_invalid")
                binding = ApprovalBinding.from_request(request, policy.policy_hash)
                if not self.approval_store.consume(
                    request.approval_id, binding, datetime.now(timezone.utc)
                ):
                    return self._closed("approval_invalid")
                outcome = evaluate_policy(effective_request, findings, policy, approved=True)
                outcome = self._minimum_outcome(outcome, findings, request.operation)
            elif outcome.action == DecisionAction.REQUIRE_APPROVAL:
                if self.approval_store is None:
                    return self._closed("approval_unavailable")
                binding = ApprovalBinding.from_request(request, policy.policy_hash)
                approval_id = self.approval_store.create(
                    binding, datetime.now(timezone.utc) + timedelta(minutes=15)
                )

            if outcome.action in {DecisionAction.BLOCK, DecisionAction.REQUIRE_APPROVAL}:
                safe_payload = None
                decision = outcome.action
            elif outcome.action == DecisionAction.SANITIZE:
                safe_payload = transform_payload(
                    request.payload, findings, outcome, request.case_id, self.mapping_store
                )
                verify_transformation(findings, safe_payload, outcome)
                decision = DecisionAction.SANITIZE
            else:
                safe_payload = request.payload
                decision = DecisionAction.ALLOW

            event = AuditEvent(
                agent_id=request.agent_id,
                case_id=request.case_id,
                operation=request.operation.value,
                decision=decision.value,
                reason_codes=outcome.reason_codes,
                injection_score=injection_score,
                privacy_score=privacy_score,
                policy_hash=policy.policy_hash,
                categories=sorted({f.category for f in findings}),
            )
            if self.policy_store and self.policy_store.active_hash() != policy.policy_hash:
                return self._closed("policy_changed")
            audit_id = self.audit_store.record(event)

            memory_id = None
            if request.operation == Operation.MEMORY_WRITE and decision in {
                DecisionAction.ALLOW,
                DecisionAction.SANITIZE,
            }:
                if self.memory_store is None:
                    return self._closed("memory_unavailable")
                if safe_payload is None:
                    return self._closed("memory_payload_unavailable")
                memory_id = uuid.uuid4().hex
                ttl = outcome.ttl_seconds or 86_400
                provenance = {
                    "source_id": source_id,
                    "trust_level": "trusted" if trusted_system else "untrusted",
                }
                self.memory_store.write(
                    MemoryRecord(
                        id=memory_id,
                        case_id=request.case_id,
                        content=safe_payload,
                        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
                        provenance=provenance,
                    )
                )

            return EvaluationResponse(
                decision=decision,
                safe_payload=safe_payload,
                findings=findings,
                reason_codes=outcome.reason_codes,
                injection_score=injection_score,
                privacy_score=privacy_score,
                policy_hash=policy.policy_hash,
                audit_id=audit_id,
                memory_id=memory_id,
                approval_id=approval_id,
            )
        except Exception:
            return self._closed("evaluation_unavailable")
