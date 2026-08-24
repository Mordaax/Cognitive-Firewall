"""Opaque, exact-match, single-use operator approvals."""

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import cast

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from cognitive_firewall.detectors.pii import detect_pii
from cognitive_firewall.detectors.secrets import detect_secrets
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
    provenance_digest: str

    @classmethod
    def for_reidentification(cls, case_id: str, token: str, policy_hash: str) -> "ApprovalBinding":
        return cls(
            case_id=case_id,
            operation="reidentify",
            policy_hash=policy_hash,
            payload_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            source="operator",
            destination="local",
            agent_id="operator",
            provenance_digest="",
        )

    @classmethod
    def from_request(cls, request: EvaluationRequest, policy_hash: str) -> "ApprovalBinding":
        raw = json.dumps(request.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        provenance = json.dumps(
            request.provenance.model_dump(mode="json") if request.provenance else None,
            sort_keys=True,
            separators=(",", ":"),
        )
        return cls(
            request.case_id,
            request.operation.value,
            policy_hash,
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            request.source,
            request.destination,
            request.agent_id,
            hashlib.sha256(provenance.encode("utf-8")).hexdigest(),
        )

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
            session.add(
                ApprovalRow(
                    id=approval_id,
                    binding_digest=binding.digest(),
                    case_id=binding.case_id,
                    status="pending",
                    expires_at=expires_at.timestamp(),
                    review_metadata={
                        "operation": binding.operation,
                        "destination": self._safe_label(binding.destination),
                        "agent_id": self._safe_label(binding.agent_id),
                        "payload_digest": binding.payload_digest,
                        "policy_hash": binding.policy_hash,
                    },
                )
            )
            self._audit(
                session,
                binding.case_id,
                binding.operation,
                binding.policy_hash,
                "require_approval",
                "approval_requested",
            )
            session.commit()
        return approval_id

    @staticmethod
    def _safe_label(value: str) -> str:
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_:/.-]{0,127}", value)
            or detect_pii(value)
            or detect_secrets(value)
        ):
            return "[redacted]"
        return value

    @staticmethod
    def _review(row: ApprovalRow) -> dict:
        return {
            "id": row.id,
            "case_id": row.case_id,
            "status": row.status,
            "expires_at": row.expires_at,
            **(row.review_metadata or {}),
        }

    def get_pending(self, approval_id: str, *, now: datetime | None = None) -> dict | None:
        now = now or datetime.now(timezone.utc)
        with self.db.session() as session:
            row = session.scalar(
                select(ApprovalRow).where(
                    ApprovalRow.id == approval_id,
                    ApprovalRow.status == "pending",
                    ApprovalRow.expires_at > now.timestamp(),
                )
            )
            return self._review(row) if row else None

    def list_pending(self, *, limit: int = 50, offset: int = 0) -> dict:
        now = datetime.now(timezone.utc).timestamp()
        with self.db.session() as session:
            condition = (ApprovalRow.status == "pending", ApprovalRow.expires_at > now)
            total = (
                session.scalar(select(func.count()).select_from(ApprovalRow).where(*condition)) or 0
            )
            rows = session.scalars(
                select(ApprovalRow)
                .where(*condition)
                .order_by(ApprovalRow.expires_at, ApprovalRow.id)
                .offset(offset)
                .limit(limit)
            ).all()
            return {"total": total, "items": [self._review(row) for row in rows]}

    def decide(self, approval_id: str, approve: bool, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        with self.db.session() as session:
            row = session.get(ApprovalRow, approval_id)
            if row is None:
                return False
            case_id = row.case_id
            result = cast(
                CursorResult,
                session.execute(
                    update(ApprovalRow)
                    .where(
                        ApprovalRow.id == approval_id,
                        ApprovalRow.status == "pending",
                        ApprovalRow.expires_at > now.timestamp(),
                    )
                    .values(status="approved" if approve else "denied")
                ),
            )
            if result.rowcount != 1:
                return False
            self._audit(
                session,
                case_id,
                "approval",
                "",
                "allow" if approve else "block",
                "approval_granted" if approve else "approval_denied",
            )
            session.commit()
        return True

    def consume(self, approval_id: str, binding: ApprovalBinding, now: datetime) -> bool:
        with self.db.session() as session:
            result = cast(
                CursorResult,
                session.execute(
                    update(ApprovalRow)
                    .where(
                        ApprovalRow.id == approval_id,
                        ApprovalRow.binding_digest == binding.digest(),
                        ApprovalRow.case_id == binding.case_id,
                        ApprovalRow.status == "approved",
                        ApprovalRow.expires_at > now.timestamp(),
                    )
                    .values(status="consumed", consumed_at=now.timestamp())
                ),
            )
            consumed = result.rowcount == 1
            if consumed:
                self._audit(
                    session,
                    binding.case_id,
                    binding.operation,
                    binding.policy_hash,
                    "allow",
                    "approval_consumed",
                )
            session.commit()
        return consumed

    def _audit(
        self,
        session: Session,
        case_id: str,
        operation: str,
        policy_hash: str,
        decision: str,
        reason: str,
    ) -> None:
        if self.audit:
            self.audit.record_in_session(
                session,
                AuditEvent(
                    agent_id="operator",
                    case_id=case_id,
                    operation=operation,
                    decision=decision,
                    reason_codes=[reason],
                    injection_score=0,
                    privacy_score=0,
                    policy_hash=policy_hash,
                ),
            )
