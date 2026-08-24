import pytest

from cognitive_firewall.schemas import EvaluationRequest
from cognitive_firewall.security.provenance import ProvenanceError, ProvenanceStore
from cognitive_firewall.storage.db import Database


def request(**changes):
    return EvaluationRequest(
        **(
            dict(
                operation="retrieval",
                payload="text",
                source="reader",
                destination="model",
                agent_id="agent",
                case_id="case",
            )
            | changes
        )
    )


def test_content_binding_and_untrusted():
    store = ProvenanceStore(Database("sqlite:///:memory:"))
    req = request(provenance={"trust_level": "trusted"})
    ref = store.issue(req, {"b": 2, "a": 1})
    assert store.verify(ref, req, {"a": 1, "b": 2}).untrusted
    assert store.verify(ref, req).untrusted
    with pytest.raises(ProvenanceError):
        store.verify(ref, req, {"a": 2})
    with pytest.raises(ProvenanceError):
        store.verify(ref, request(agent_id="other"))
    with pytest.raises(ProvenanceError):
        store.verify(ref, request(case_id="other"))
    with pytest.raises(ProvenanceError):
        store.verify("unknown", req)


def test_parent_lineage_and_expiry(monkeypatch):
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 100)
    store = ProvenanceStore(Database("sqlite:///:memory:"), ttl_seconds=10)
    req = request()
    parent = store.issue(req, "parent")
    child = store.issue(req, "child", [parent])
    assert store.verify(child, req, "child").parent_ids == (parent,)
    with pytest.raises(ProvenanceError):
        store.issue(request(agent_id="other"), "child", [parent])
    with pytest.raises(ProvenanceError):
        store.issue(req, "child", ["unknown"])
    with pytest.raises(ProvenanceError):
        store.issue(req, "child", [parent] * 33)
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 110)
    with pytest.raises(ProvenanceError):
        store.verify(child, req)
    with pytest.raises(ProvenanceError):
        store.issue(req, "descendant", [parent])


def test_transitive_binding_and_persistence():
    db = Database("sqlite:///:memory:")
    store = ProvenanceStore(db)
    req = request()
    parent = store.issue(req, "parent")
    child = store.issue(req, "child", [parent])
    grandchild = store.issue(req, "grandchild", [child])
    assert ProvenanceStore(db).verify(grandchild, req).untrusted
    assert store.issue(req, "same") != store.issue(req, "same")
    with pytest.raises(ProvenanceError):
        store.verify(parent, req, {"text": "parent"})
    with pytest.raises(ProvenanceError):
        store.issue(req, {"value": float("nan")})
    # Storage contains digests and lineage only; raw source content is not retained.
    from sqlalchemy import text

    with db.engine.connect() as connection:
        row = connection.execute(
            text("SELECT * FROM provenance_references WHERE id=:id"), {"id": parent}
        ).one()
        assert "parent" not in tuple(row)


@pytest.mark.parametrize("ttl", [0, -1, float("inf"), float("nan")])
def test_invalid_ttl(ttl):
    with pytest.raises(ValueError):
        ProvenanceStore(Database("sqlite:///:memory:"), ttl_seconds=ttl)


def test_case_taint_sticky_scoped_and_expiring(monkeypatch):
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 100)
    db = Database("sqlite:///:memory:")
    store = ProvenanceStore(db, ttl_seconds=10)
    req = request()
    assert not store.case_is_untrusted(req)
    store.mark_untrusted(req)
    assert ProvenanceStore(db).case_is_untrusted(req)
    assert not store.case_is_untrusted(request(agent_id="other"))
    assert not store.case_is_untrusted(request(case_id="other"))
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 105)
    store.mark_untrusted(req)
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 110)
    assert store.case_is_untrusted(req)
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 115)
    assert not store.case_is_untrusted(req)


def test_case_taint_ttl_capped(monkeypatch):
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 0)
    store = ProvenanceStore(Database("sqlite:///:memory:"), ttl_seconds=200000)
    req = request()
    store.mark_untrusted(req)
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 86400)
    assert not store.case_is_untrusted(req)


def test_ancestry_work_bounded():
    from cognitive_firewall.security.provenance import _Reference

    db = Database("sqlite:///:memory:")
    store = ProvenanceStore(db)
    req = request()
    ref = store.issue(req, "root")
    with db.session() as session:
        row = session.get(_Reference, ref)
        row.parent_ids = ["node0"]
        for i in range(1024):
            session.add(
                _Reference(
                    id=f"node{i}",
                    agent_id=req.agent_id,
                    case_id=req.case_id,
                    content_hash=row.content_hash,
                    expires_at=row.expires_at,
                    parent_ids=[f"node{i + 1}"] if i < 1023 else [],
                )
            )
        session.commit()
    with pytest.raises(ProvenanceError, match="ancestry"):
        store.verify(ref, req)


def test_agent_taint_cannot_be_reset_by_case_swap(monkeypatch):
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 100)
    store = ProvenanceStore(Database("sqlite:///:memory:"), ttl_seconds=10)
    store.mark_untrusted(request())
    assert store.agent_is_untrusted(request(case_id="fresh-case"))
    assert not store.agent_is_untrusted(request(agent_id="another-agent"))
    monkeypatch.setattr("cognitive_firewall.security.provenance.time.time", lambda: 110)
    assert not store.agent_is_untrusted(request())
