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
from cognitive_firewall.security.tools import ToolRegistry
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
        tool_registry: ToolRegistry | None = None,
        provenance_store: Any | None = None,
        semantic_detector: Any | None = None,
        semantic_threshold: float = 0.8,
    ):
        self.policy = policy
        self.audit_store = audit_store
        self.mapping_store = mapping_store
        self.memory_store = memory_store
        self.approval_store = approval_store
        self.trusted_system_hashes = trusted_system_hashes or {}
        self.policy_store = policy_store
        self.tool_registry = tool_registry or ToolRegistry.from_dict({"tools": {}})
        self.provenance_store = provenance_store
        self.semantic_detector = semantic_detector
        if not 0 < semantic_threshold <= 1:
            raise ValueError("semantic threshold must be in (0, 1]")
        self.semantic_threshold = semantic_threshold

    def _closed(self, reason: str, request: EvaluationRequest | None = None) -> EvaluationResponse:
        audit_id = ""
        if request is not None:
            try:
                audit_id = self.audit_store.record(AuditEvent(
                    agent_id=request.agent_id, case_id=request.case_id,
                    operation=request.operation.value, decision="block", reason_codes=[reason],
                    injection_score=0, privacy_score=0,
                    policy_hash=self.policy.policy_hash if self.policy else ""))
            except Exception:
                pass
        return EvaluationResponse(
            decision=DecisionAction.BLOCK,
            safe_payload=None,
            findings=[],
            reason_codes=[reason],
            injection_score=0,
            privacy_score=0,
            policy_hash=self.policy.policy_hash if self.policy else "",
            audit_id=audit_id,
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
                return self._closed("policy_unavailable", request)
            tool_approval = False
            if request.operation == Operation.TOOL_REQUEST:
                try:
                    tool_approval = self.tool_registry.check(request)
                except PermissionError:
                    return self._closed("tool_not_authorized", request)
            parents = list(request.lineage_ids)
            if request.provenance_id:
                if self.provenance_store is None:
                    return self._closed("provenance_unavailable", request)
                self.provenance_store.verify(request.provenance_id, request, request.payload)
                parents.append(request.provenance_id)
            if parents and self.provenance_store is None:
                return self._closed("provenance_unavailable", request)
            for parent in parents:
                self.provenance_store.verify(parent, request)
            external = request.operation in {
                Operation.RETRIEVAL, Operation.TOOL_RESULT,
                Operation.MEMORY_READ, Operation.MODEL_OUTPUT,
            }
            if self.provenance_store and (external or parents):
                self.provenance_store.mark_untrusted(request)
            tainted = bool(parents) or bool(
                self.provenance_store and self.provenance_store.agent_is_untrusted(request))
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
            if self.semantic_detector is not None and not trusted_system:
                try:
                    semantic_score = self.semantic_detector.score(request.payload)
                    import math
                    if (not isinstance(semantic_score, (float, int))
                            or isinstance(semantic_score, bool)
                            or not math.isfinite(semantic_score) or not 0 <= semantic_score <= 1):
                        return self._closed("semantic_unavailable", request)
                except Exception:
                    return self._closed("semantic_unavailable", request)
                if semantic_score >= self.semantic_threshold:
                    findings.append(Finding(category="injection", severity=90,
                                            reason_code="semantic_injection", detector="semantic"))
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

            # These controls cannot be weakened by editing text-screening policy.
            needs_approval = (tool_approval or request.operation == Operation.MEMORY_WRITE
                              or (tainted and request.operation in {
                                  Operation.TOOL_REQUEST, Operation.EXPORT}))
            if needs_approval and outcome.action != DecisionAction.BLOCK:
                outcome = outcome.model_copy(update={
                    "action": DecisionAction.REQUIRE_APPROVAL,
                    "reason_codes": outcome.reason_codes + ["capability_approval_required"],
                })
            binding = ApprovalBinding.from_request(
                request, policy.policy_hash, self.tool_registry.policy_hash)

            approval_id = None
            if request.approval_id and not unsafe_key:
                if outcome.action != DecisionAction.REQUIRE_APPROVAL or self.approval_store is None:
                    return self._closed("approval_invalid", request)
                if not self.approval_store.consume(
                    request.approval_id, binding, datetime.now(timezone.utc)
                ):
                    return self._closed("approval_invalid", request)
                outcome = evaluate_policy(effective_request, findings, policy, approved=True)
                outcome = self._minimum_outcome(outcome, findings, request.operation)
                # Registered actions/lineage may have required review independently
                # of YAML; an exact approval discharges that requirement only.
            elif outcome.action == DecisionAction.REQUIRE_APPROVAL:
                if self.approval_store is None:
                    return self._closed("approval_unavailable", request)
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

            # Never execute transformed arguments under an approval for a different
            # action. Submit the sanitized object separately for a fresh decision.
            if (request.operation == Operation.TOOL_REQUEST
                    and safe_payload is not None and safe_payload != request.payload):
                return self._closed("tool_arguments_transformed", request)

            provenance_id = None
            if self.provenance_store and safe_payload is not None:
                provenance_id = self.provenance_store.issue(request, safe_payload, parents)

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
                return self._closed("policy_changed", request)
            audit_id = self.audit_store.record(event)

            memory_id = None
            if request.operation == Operation.MEMORY_WRITE and decision in {
                DecisionAction.ALLOW,
                DecisionAction.SANITIZE,
            }:
                if self.memory_store is None:
                    return self._closed("memory_unavailable", request)
                if safe_payload is None:
                    return self._closed("memory_payload_unavailable", request)
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
                provenance_id=provenance_id,
            )
        except Exception:
            return self._closed("evaluation_unavailable", request)
