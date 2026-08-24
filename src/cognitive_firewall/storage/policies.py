"""Store policy activation history without raw policy secrets."""

from __future__ import annotations

from sqlalchemy import select, update

from cognitive_firewall.policy.models import PolicyBundle
from cognitive_firewall.storage.db import Database, PolicyRow


class SqlPolicyStore:
    def __init__(self, db: Database):
        self.db = db

    def activate(self, policy: PolicyBundle) -> None:
        with self.db.session() as session:
            session.execute(update(PolicyRow).values(active=False))
            session.merge(PolicyRow(policy_hash=policy.policy_hash, version=policy.version, active=True))
            session.commit()

    def active_hash(self) -> str | None:
        with self.db.session() as session:
            row = session.scalar(select(PolicyRow).where(PolicyRow.active.is_(True)))
            return row.policy_hash if row else None
