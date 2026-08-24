"""Shared admission controller used by all adapters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
from typing import Any

from cognitive_firewall.detectors.injection import detect_injection
from cognitive_firewall.detectors.pii import detect_pii
from cognitive_firewall.detectors.secrets import detect_secrets
from cognitive_firewall.policy.evaluator import evaluate_policy
from cognitive_firewall.policy.models import PolicyBundle
from cognitive_firewall.risk import score_findings
from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, EvaluationResponse, Finding, Operation, Provenance
from cognitive_firewall.storage.audit import AuditEvent
from cognitive_firewall.storage.memory import MemoryRecord
from cognitive_firewall.transforms.redaction import transform_payload
from cognitive_firewall.transforms.verification import verify_transformation


class Evaluator:
    def __init__(self, policy: PolicyBundle | None, audit_store: Any, mapping_store: Any,
                 memory_store: Any | None = None, approval_store: Any | None = None,
                 trusted_system_hashes: dict[str, str] | None = None):
        self.policy = policy
        self.audit_store = audit_store
        self.mapping_store = mapping_store
        self.memory_store = memory_store
        self.approval_store = approval_store
        self.trusted_system_hashes = trusted_system_hashes or {}

    def _closed(self, reason: str) -> EvaluationResponse:
        return EvaluationResponse(decision=DecisionAction.BLOCK, safe_payload=None, findings=[],
                                  reason_codes=[reason], injection_score=0, privacy_score=0,
                                  policy_hash=self.policy.policy_hash if self.policy else "", audit_id="")

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        if self.policy is None:
            return self._closed("policy_unavailable")
        try:
            source_id = request.provenance.source_id if request.provenance else ""
            system_digest = hashlib.sha256(request.payload.encode("utf-8")).hexdigest() if isinstance(request.payload, str) else ""
            trusted_system = (request.source == "system" and self.trusted_system_hashes.get(source_id) == system_digest
                              and bool(system_digest))
            effective_request = request.model_copy(update={"provenance": Provenance(
                source_id=source_id, trust_level="trusted" if trusted_system else "untrusted")})
            findings = [] if trusted_system else detect_injection(request.payload, source=request.source)
            if request.source == "system" and not trusted_system:
                findings.append(Finding(category="injection", severity=100,
                                        reason_code="system_prompt_unrecognized", detector="provenance"))
            findings += detect_pii(request.payload)
            findings += detect_secrets(request.payload)
            injection_score, privacy_score = score_findings(findings)
            outcome = evaluate_policy(effective_request, findings, self.policy)

            if outcome.action in {DecisionAction.BLOCK, DecisionAction.REQUIRE_APPROVAL}:
                safe_payload = None
                decision = outcome.action
            elif outcome.action == DecisionAction.SANITIZE:
                safe_payload = transform_payload(request.payload, findings, outcome, request.case_id, self.mapping_store)
                verify_transformation(findings, safe_payload, outcome)
                decision = DecisionAction.SANITIZE
            else:
                safe_payload = request.payload
                decision = DecisionAction.ALLOW

            event = AuditEvent(agent_id=request.agent_id, case_id=request.case_id,
                               operation=request.operation.value, decision=decision.value,
                               reason_codes=outcome.reason_codes, injection_score=injection_score,
                               privacy_score=privacy_score, policy_hash=self.policy.policy_hash,
                               categories=sorted({f.category for f in findings}))
            audit_id = self.audit_store.record(event)

            memory_id = None
            if request.operation == Operation.MEMORY_WRITE and decision in {DecisionAction.ALLOW, DecisionAction.SANITIZE}:
                if self.memory_store is None:
                    return self._closed("memory_unavailable")
                memory_id = uuid.uuid4().hex
                ttl = outcome.ttl_seconds or 86_400
                provenance = request.provenance.model_dump() if request.provenance else {"source_id": request.source, "trust_level": "untrusted"}
                self.memory_store.write(MemoryRecord(id=memory_id, case_id=request.case_id, content=safe_payload,
                                                     expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
                                                     provenance=provenance))

            return EvaluationResponse(decision=decision, safe_payload=safe_payload, findings=findings,
                                      reason_codes=outcome.reason_codes, injection_score=injection_score,
                                      privacy_score=privacy_score, policy_hash=self.policy.policy_hash,
                                      audit_id=audit_id, memory_id=memory_id)
        except Exception:
            return self._closed("evaluation_unavailable")
