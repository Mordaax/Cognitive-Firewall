from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from cognitive_firewall.storage.audit import AuditEvent, SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore
from cognitive_firewall.storage.memory import MemoryRecord, SqlMemoryStore


def database():
    db = Database("sqlite:///:memory:")
    db.create_all()
    return db


def test_audit_rows_contain_no_raw_sensitive_value():
    db = database()
    store = SqlAuditStore(db)
    audit_id = store.record(
        AuditEvent(
            agent_id="a1",
            case_id="c1",
            operation="model_input",
            decision="sanitize",
            reason_codes=["internal_privacy"],
            injection_score=0,
            privacy_score=65,
            policy_hash="abc",
            categories=["email"],
        )
    )
    assert audit_id
    with db.session() as session:
        data = session.execute(text("select * from audit_events")).all()
    assert "alice@example.com" not in str(data)


def test_mapping_is_case_scoped_and_encrypted():
    db = database()
    store = SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32)
    one = store.get_or_create("case-1", "email", "alice@example.com")
    assert store.get_or_create("case-1", "email", "alice@example.com") == one
    assert store.get_or_create("case-2", "email", "alice@example.com") != one
    assert store.reidentify("case-1", one) == "alice@example.com"
    with db.session() as session:
        rows = session.execute(text("select ciphertext from mappings")).all()
    assert "alice@example.com" not in str(rows)


def test_memory_ttl_is_checked_on_read_before_cleanup():
    db = database()
    store = SqlMemoryStore(db)
    now = datetime.now(timezone.utc)
    store.write(
        MemoryRecord(
            id="m1",
            case_id="c1",
            content={"email": "EMAIL_01"},
            expires_at=now + timedelta(seconds=3),
            provenance={"source_id": "tool-1"},
        )
    )
    assert store.read("m1", now=now) is not None
    assert store.read("m1", now=now + timedelta(seconds=4)) is None
