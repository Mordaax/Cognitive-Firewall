"""Opaque, exact-match, single-use operator approvals."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import secrets

from sqlalchemy import update

from cognitive_firewall.schemas import EvaluationRequest
from cognitive_firewall.storage.audit import AuditEvent, SqlAuditStore
from cognitive_firewall.storage.db import ApprovalRow, Database


@dataclass(frozen=True)
class ApprovalBinding:
    case_id: str
    operation: str
    policy_hash: str
    payload_digest: str
    source: str
    destination: str
    agent_id: str

    @classmethod
    def from_request(cls, request: EvaluationRequest, policy_hash: str) -> "ApprovalBinding":
        raw = json.dumps(request.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return cls(request.case_id, request.operation.value, policy_hash,
                   hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                   request.source, request.destination, request.agent_id)

    def digest(self) -> str:
        raw = json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApprovalStore:
    def __init__(self, db: Database, audit: SqlAuditStore | None = None):
        self.db = db
        self.audit = audit

    def create(self, binding: ApprovalBinding, expires_at: datetime) -> str:
        approval_id = secrets.token_urlsafe(32)
        with self.db.session() as session:
            session.add(ApprovalRow(id=approval_id, binding_digest=binding.digest(),
                                    case_id=binding.case_id, status="pending",
                                    expires_at=expires_at.timestamp()))
            session.commit()
        self._audit(binding.case_id, binding.operation, binding.policy_hash, "require_approval", "approval_requested")
        return approval_id

    def decide(self, approval_id: str, approve: bool, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        with self.db.session() as session:
            row = session.get(ApprovalRow, approval_id)
            if row is None or row.status != "pending" or row.expires_at <= now.timestamp():
                return False
            row.status = "approved" if approve else "denied"
            case_id = row.case_id
            session.commit()
        self._audit(case_id, "approval", "", "allow" if approve else "block",
                    "approval_granted" if approve else "approval_denied")
        return True

    def consume(self, approval_id: str, binding: ApprovalBinding, now: datetime) -> bool:
        with self.db.session() as session:
            result = session.execute(update(ApprovalRow).where(
                ApprovalRow.id == approval_id,
                ApprovalRow.binding_digest == binding.digest(),
                ApprovalRow.case_id == binding.case_id,
                ApprovalRow.status == "approved",
                ApprovalRow.expires_at > now.timestamp(),
            ).values(status="consumed", consumed_at=now.timestamp()))
            session.commit()
            consumed = result.rowcount == 1
        if consumed:
            self._audit(binding.case_id, binding.operation, binding.policy_hash, "allow", "approval_consumed")
        return consumed

    def _audit(self, case_id: str, operation: str, policy_hash: str, decision: str, reason: str) -> None:
        if self.audit:
            self.audit.record(AuditEvent(agent_id="operator", case_id=case_id, operation=operation,
                                         decision=decision, reason_codes=[reason], injection_score=0,
                                         privacy_score=0, policy_hash=policy_hash))
