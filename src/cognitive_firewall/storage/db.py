"""SQLAlchemy schema shared by SQLite and Postgres."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import (
    JSON,
    Float,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class AuditRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    agent_id: Mapped[str] = mapped_column(String(128))
    case_id: Mapped[str] = mapped_column(String(128))
    operation: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(32))
    reason_codes: Mapped[list[str]] = mapped_column(JSON)
    categories: Mapped[list[str]] = mapped_column(JSON)
    injection_score: Mapped[int] = mapped_column(Integer)
    privacy_score: Mapped[int] = mapped_column(Integer)
    policy_hash: Mapped[str] = mapped_column(String(64))


class MappingRow(Base):
    __tablename__ = "mappings"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(32))
    digest: Mapped[str] = mapped_column(String(64))
    token: Mapped[str] = mapped_column(String(80))
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    __table_args__ = (
        UniqueConstraint("case_id", "category", "digest"),
        UniqueConstraint("case_id", "token"),
    )


class MemoryRow(Base):
    __tablename__ = "memory_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    content: Mapped[str | dict[str, Any]] = mapped_column(JSON)
    provenance: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[float] = mapped_column(Float, index=True)


class ApprovalRow(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    binding_digest: Mapped[str] = mapped_column(String(64))
    case_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    expires_at: Mapped[float] = mapped_column(Float)
    consumed_at: Mapped[float | None] = mapped_column(Float, nullable=True)


class PolicyRow(Base):
    __tablename__ = "policy_versions"
    policy_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    activated_at: Mapped[float] = mapped_column(Float, default=time.time)
    active: Mapped[bool] = mapped_column(default=False)
    policy_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)


class Database:
    def __init__(self, url: str):
        kwargs: dict[str, Any] = {"future": True}
        if url == "sqlite:///:memory:":
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = StaticPool
        elif url.startswith("sqlite:"):
            kwargs["connect_args"] = {"check_same_thread": False}
        self.engine = create_engine(url, **kwargs)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)
        # Upgrade databases created by the first pilot schema.
        if "policy_yaml" not in {
            column["name"] for column in inspect(self.engine).get_columns("policy_versions")
        }:
            with self.engine.begin() as connection:
                connection.execute(text("ALTER TABLE policy_versions ADD COLUMN policy_yaml TEXT"))

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as session:
            yield session
