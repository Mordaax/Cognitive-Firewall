"""Opaque, server-issued references retaining untrusted content lineage."""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import JSON, Float, String, case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from cognitive_firewall.schemas import EvaluationRequest
from cognitive_firewall.storage.db import Database


class ProvenanceError(ValueError):
    """A provenance reference is missing, expired, or outside its binding."""


class _Base(DeclarativeBase):
    pass


class _Reference(_Base):
    __tablename__ = "provenance_references"
    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(128))
    case_id: Mapped[str] = mapped_column(String(128))
    content_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float)
    parent_ids: Mapped[list[str]] = mapped_column(JSON)


class _CaseTaint(_Base):
    __tablename__ = "provenance_case_taint"
    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[float] = mapped_column(Float)


@dataclass(frozen=True)
class ProvenanceRecord:
    reference: str
    agent_id: str
    case_id: str
    content_hash: str
    expires_at: float
    parent_ids: tuple[str, ...]
    untrusted: bool = True


def _digest(content: str | dict[str, Any]) -> str:
    if not isinstance(content, (str, dict)):
        raise ProvenanceError("content must be text or an object")
    try:
        encoded = json.dumps(
            content, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ProvenanceError("content is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


class ProvenanceStore:
    def __init__(self, db: Database, ttl_seconds: float = 86400):
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("provenance TTL must be positive and finite")
        self.db = db
        self.ttl_seconds = ttl_seconds
        _Base.metadata.create_all(db.engine)

    def mark_untrusted(self, request: EvaluationRequest) -> None:
        """Retain taint for this agent/case, extending but never shortening TTL."""
        expires = time.time() + min(self.ttl_seconds, 86400)
        statement = (
            update(_CaseTaint)
            .where(_CaseTaint.agent_id == request.agent_id, _CaseTaint.case_id == request.case_id)
            .values(
                expires_at=case(
                    (_CaseTaint.expires_at < expires, expires),
                    else_=_CaseTaint.expires_at,
                )
            )
        )
        with self.db.session() as session:
            if session.execute(statement).rowcount:
                session.commit()
                return
            session.add(
                _CaseTaint(agent_id=request.agent_id, case_id=request.case_id, expires_at=expires)
            )
            try:
                session.commit()
            except IntegrityError:
                # A concurrent host created the same case after our UPDATE.
                session.rollback()
                session.execute(statement)
                session.commit()

    def case_is_untrusted(self, request: EvaluationRequest) -> bool:
        with self.db.session() as session:
            row = session.get(_CaseTaint, (request.agent_id, request.case_id))
            return row is not None and row.expires_at > time.time()

    def agent_is_untrusted(self, request: EvaluationRequest) -> bool:
        """Prevent caller-selected case identifiers from erasing known taint."""
        with self.db.session() as session:
            return (
                session.scalar(
                    select(_CaseTaint.agent_id)
                    .where(
                        _CaseTaint.agent_id == request.agent_id,
                        _CaseTaint.expires_at > time.time(),
                    )
                    .limit(1)
                )
                is not None
            )

    def issue(
        self,
        request: EvaluationRequest,
        content: str | dict[str, Any],
        parent_ids: list[str] | None = None,
    ) -> str:
        parents = list(parent_ids or [])
        if len(parents) > 32:
            raise ProvenanceError("at most 32 provenance parents are permitted")
        now = time.time()
        expires = now + self.ttl_seconds
        # Validate the complete ancestry, including ancestors whose TTL has elapsed.
        for parent in parents:
            record = self.verify(parent, request)
            expires = min(expires, record.expires_at)
        reference = "prov_" + secrets.token_urlsafe(32)
        row = _Reference(
            id=reference,
            agent_id=request.agent_id,
            case_id=request.case_id,
            content_hash=_digest(content),
            expires_at=expires,
            parent_ids=list(dict.fromkeys(parents)),
        )
        with self.db.session() as session:
            session.add(row)
            session.commit()
        return reference

    def verify(
        self,
        reference: str,
        request: EvaluationRequest,
        content: str | dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        now = time.time()
        seen: set[str] = set()
        pending = [reference]
        root = None
        with self.db.session() as session:
            while pending:
                current = pending.pop()
                if not isinstance(current, str) or not current:
                    raise ProvenanceError("invalid provenance reference")
                if current in seen:
                    continue
                seen.add(current)
                if len(seen) > 1024:
                    raise ProvenanceError("provenance ancestry exceeds verification limit")
                row = session.get(_Reference, current)
                if (
                    row is None
                    or row.agent_id != request.agent_id
                    or row.case_id != request.case_id
                    or row.expires_at <= now
                ):
                    raise ProvenanceError("unknown, expired, or mismatched provenance")
                if current == reference:
                    root = ProvenanceRecord(
                        row.id,
                        row.agent_id,
                        row.case_id,
                        row.content_hash,
                        row.expires_at,
                        tuple(row.parent_ids),
                    )
                pending.extend(row.parent_ids)
        if root is None:
            raise ProvenanceError("invalid provenance reference")
        if content is not None and not secrets.compare_digest(root.content_hash, _digest(content)):
            raise ProvenanceError("provenance content mismatch")
        return root
