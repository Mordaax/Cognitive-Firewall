"""Aggregated telemetry and allowlisted audit export."""

from dataclasses import asdict, dataclass
import json
import time

from sqlalchemy import select

from cognitive_firewall.storage.db import AuditRow, Database


@dataclass(frozen=True)
class AgentSummary:
    agent_id: str
    total: int
    blocked: int
    sanitized: int
    allowed: int
    approvals: int
    mean_injection_score: float
    mean_privacy_score: float
    policy_versions: list[str]


class ReportStore:
    def __init__(self, db: Database):
        self.db = db

    def _rows(self, agent_id: str | None = None, since: float | None = None) -> list[AuditRow]:
        statement = select(AuditRow)
        if agent_id:
            statement = statement.where(AuditRow.agent_id == agent_id)
        if since is not None:
            statement = statement.where(AuditRow.created_at >= since)
        with self.db.session() as session:
            return list(session.scalars(statement).all())

    def agent_summary(self, agent_id: str, window: int = 86_400) -> AgentSummary:
        rows = self._rows(agent_id, time.time() - window)
        count = len(rows)
        return AgentSummary(agent_id=agent_id, total=count,
                            blocked=sum(row.decision == "block" for row in rows),
                            sanitized=sum(row.decision == "sanitize" for row in rows),
                            allowed=sum(row.decision == "allow" for row in rows),
                            approvals=sum(row.decision == "require_approval" for row in rows),
                            mean_injection_score=round(sum(row.injection_score for row in rows) / count, 2) if count else 0,
                            mean_privacy_score=round(sum(row.privacy_score for row in rows) / count, 2) if count else 0,
                            policy_versions=sorted({row.policy_hash for row in rows if row.policy_hash}))

    def summary(self, window: int = 86_400) -> dict:
        rows = self._rows(since=time.time() - window)
        agents = sorted({row.agent_id for row in rows})
        count = len(rows)
        return {"total": count, "blocked": sum(row.decision == "block" for row in rows),
                "sanitized": sum(row.decision == "sanitize" for row in rows),
                "allowed": sum(row.decision == "allow" for row in rows),
                "approvals": sum(row.decision == "require_approval" for row in rows),
                "policy_versions": sorted({row.policy_hash for row in rows if row.policy_hash}),
                "agents": [asdict(self.agent_summary(agent_id, window)) for agent_id in agents]}

    def export_redacted(self, *, agent_id: str | None = None, window: int = 86_400) -> bytes:
        rows = self._rows(agent_id, time.time() - window)
        events = [{"id": row.id, "created_at": row.created_at, "agent_id": row.agent_id,
                   "operation": row.operation, "decision": row.decision,
                   "reason_codes": row.reason_codes, "categories": row.categories,
                   "injection_score": row.injection_score, "privacy_score": row.privacy_score,
                   "policy_hash": row.policy_hash} for row in rows]
        return json.dumps({"events": events, "total": len(events)}, separators=(",", ":")).encode()
