"""Store policy activation history without raw policy secrets."""

from __future__ import annotations

from sqlalchemy import select, update

from cognitive_firewall.policy.loader import load_policy_bytes
from cognitive_firewall.policy.models import PolicyBundle
from cognitive_firewall.storage.db import Database, PolicyRow


class SqlPolicyStore:
    def __init__(self, db: Database):
        self.db = db

    def activate(self, policy: PolicyBundle, raw_yaml: bytes | None = None) -> None:
        with self.db.session() as session:
            session.execute(update(PolicyRow).values(active=False))
            session.merge(
                PolicyRow(
                    policy_hash=policy.policy_hash,
                    version=policy.version,
                    active=True,
                    policy_yaml=raw_yaml.decode("utf-8") if raw_yaml else None,
                )
            )
            session.commit()

    def active_bundle(self) -> PolicyBundle | None:
        with self.db.session() as session:
            row = session.scalar(select(PolicyRow).where(PolicyRow.active.is_(True)))
            if row is None or not row.policy_yaml:
                return None
            bundle = load_policy_bytes(row.policy_yaml.encode("utf-8"))
            if bundle.policy_hash != row.policy_hash:
                raise ValueError("stored policy hash mismatch")
            return bundle

    def active_hash(self) -> str | None:
        with self.db.session() as session:
            row = session.scalar(select(PolicyRow).where(PolicyRow.active.is_(True)))
            return row.policy_hash if row else None
