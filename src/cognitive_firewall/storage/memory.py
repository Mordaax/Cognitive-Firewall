"""Sanitized memory records with read-time TTL enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cognitive_firewall.storage.db import Database, MemoryRow


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    case_id: str
    content: str | dict[str, Any]
    expires_at: datetime
    provenance: dict[str, Any]


class SqlMemoryStore:
    def __init__(self, db: Database):
        self.db = db

    def write(self, record: MemoryRecord) -> None:
        with self.db.session() as session:
            session.merge(
                MemoryRow(
                    id=record.id,
                    case_id=record.case_id,
                    content=record.content,
                    expires_at=record.expires_at.timestamp(),
                    provenance=record.provenance,
                )
            )
            session.commit()

    def read(self, record_id: str, *, now: datetime | None = None) -> MemoryRecord | None:
        check_at = now or datetime.now(timezone.utc)
        with self.db.session() as session:
            row = session.get(MemoryRow, record_id)
            if row is None or row.expires_at <= check_at.timestamp():
                return None
            return MemoryRecord(
                id=row.id,
                case_id=row.case_id,
                content=row.content,
                expires_at=datetime.fromtimestamp(row.expires_at, timezone.utc),
                provenance=row.provenance,
            )
