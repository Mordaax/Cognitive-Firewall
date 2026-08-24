from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from cognitive_firewall.api.app import create_app
from cognitive_firewall.config import Settings
from cognitive_firewall.schemas import EvaluationRequest
from cognitive_firewall.storage.db import MemoryRow
from examples.langgraph_agent import _mock_engine


def request(**changes):
    body = dict(operation="retrieval", payload="The public document has two sections.",
                source="retrieval", destination="model", case_id="task-1", agent_id="demo-agent")
    body.update(changes)
    return EvaluationRequest(**body)


def test_api_identity_binding_and_batch_are_not_bypassed_by_operator_or_second_agent():
    settings = Settings("agent-secret", "operator-secret", "e" * 32, "h" * 32,
                        database_url="sqlite:///:memory:", agent_tokens={"second-agent": "second-secret"})
    with TestClient(create_app(settings)) as api:
        first = request(operation="model_input", payload="ordinary", source="user", destination="openai")
        for token in ["second-secret", "operator-secret"]:
            assert api.post("/v1/evaluations", json=first.model_dump(),
                            headers={"Authorization": f"Bearer {token}"}).status_code == 403
        assert api.post("/v1/evaluations", json=first.model_copy(update={"agent_id": "second-agent"}).model_dump(),
                        headers={"Authorization": "Bearer second-secret"}).status_code == 200
        batch = [first.model_dump(), first.model_copy(update={"agent_id": "second-agent"}).model_dump()]
        assert api.post("/v1/evaluations/batch", json=batch,
                        headers={"Authorization": "Bearer agent-secret"}).status_code == 403
        assert api.get("/v1/security/status", headers={"Authorization": "Bearer agent-secret"}).status_code == 403


def test_omitting_lineage_and_switching_case_cannot_erase_agent_taint():
    engine = _mock_engine()
    admitted = engine.evaluate(request())
    assert admitted.provenance_id
    action = request(operation="tool_request", payload={"query": "lookup ticket"},
                     source="agent", destination="tool:ticket", case_id="new-case")
    pending = engine.evaluate(action)
    assert pending.decision == "require_approval"
    assert engine.approval_store.decide(pending.approval_id, True)
    approved = action.model_copy(update={"approval_id": pending.approval_id})
    assert engine.evaluate(approved).decision == "allow"
    assert engine.evaluate(approved).decision == "block"
    assert engine.evaluate(request(operation="export", source="agent", destination="file",
                                   payload="Just an ordinary summary", case_id="another-case")).decision == "require_approval"


def test_provenance_content_and_ownership_are_checked_before_provider_admission():
    engine = _mock_engine()
    initial = engine.evaluate(request())
    same = request(operation="model_input", source="user", destination="openai",
                   provenance_id=initial.provenance_id)
    assert engine.evaluate(same).decision == "allow"
    for changed in [same.model_copy(update={"payload": "modified"}),
                    same.model_copy(update={"agent_id": "second-agent"}),
                    same.model_copy(update={"case_id": "other-case"})]:
        assert engine.evaluate(changed).decision == "block"


def test_tool_policy_change_invalidates_already_granted_approval():
    from cognitive_firewall.security.tools import ToolRegistry

    engine = _mock_engine()
    action = request(operation="tool_request", destination="privileged:restart",
                     source="agent", payload={"service": "demo"})
    pending = engine.evaluate(action)
    assert engine.approval_store.decide(pending.approval_id, True)
    config = __import__("yaml").safe_load(Path("policies/tools.yaml").read_text())
    config["tools"]["privileged:restart"]["input_schema"]["properties"]["service"]["enum"].append("other")
    engine.tool_registry = ToolRegistry.from_dict(config)
    assert engine.evaluate(action.model_copy(update={"approval_id": pending.approval_id})).decision == "block"


def test_provenance_failure_does_not_persist_a_memory(monkeypatch):
    engine = _mock_engine()
    action = request(operation="memory_write", source="agent", destination="memory", payload="A harmless note")
    pending = engine.evaluate(action)
    assert engine.approval_store.decide(pending.approval_id, True)

    def fail_issue(*args, **kwargs):
        raise OSError("storage unavailable")

    monkeypatch.setattr(engine.provenance_store, "issue", fail_issue)
    response = engine.evaluate(action.model_copy(update={"approval_id": pending.approval_id}))
    assert response.decision == "block"
    with engine.memory_store.db.session() as session:
        assert session.scalar(select(func.count()).select_from(MemoryRow)) == 0


def test_semantic_detector_cannot_override_policy_or_fail_open():
    import pytest

    from cognitive_firewall.sdk.guard import AgentGuard, EgressDenied

    class Detector:
        def score(self, payload):
            if payload == "trigger unavailable":
                raise RuntimeError("classifier failed")
            return 0.99 if payload == "a semantic attack fixture" else 0.0

    engine = _mock_engine()
    engine.semantic_detector = Detector()
    for text in ["a semantic attack fixture", "trigger unavailable", "sk-" + "a" * 32]:
        req = request(operation="model_input", source="user", destination="openai", payload=text)
        with pytest.raises(EgressDenied):
            AgentGuard(engine).before_model(req)
    assert engine.evaluate(request(operation="model_input", source="user", destination="openai",
                                   payload="A plain public question")).decision == "allow"
