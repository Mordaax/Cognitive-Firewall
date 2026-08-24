"""Minimal sanitized audit event persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
import uuid

from cognitive_firewall.storage.db import AuditRow, Database


@dataclass(frozen=True)
class AuditEvent:
    agent_id: str
    case_id: str
    operation: str
    decision: str
    reason_codes: list[str]
    injection_score: int
    privacy_score: int
    policy_hash: str
    categories: list[str] = field(default_factory=list)


class SqlAuditStore:
    def __init__(self, db: Database):
        self.db = db

    def record(self, event: AuditEvent) -> str:
        audit_id = uuid.uuid4().hex
        with self.db.session() as session:
            session.add(AuditRow(id=audit_id, **event.__dict__))
            session.commit()
        return audit_id
