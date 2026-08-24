from fastapi.testclient import TestClient

from cognitive_firewall.api.app import create_app
from cognitive_firewall.config import Settings


AGENT = {"Authorization": "Bearer agent-secret"}
OPERATOR = {"Authorization": "Bearer operator-secret"}


def client():
    settings = Settings("agent-secret", "operator-secret", "e" * 32, "h" * 32,
                        database_url="sqlite:///:memory:", policy_path="policies/default.yaml")
    return TestClient(create_app(settings))


def payload(text="alice@example.com", **changes):
    result = dict(operation="model_input", payload=text, source="user", destination="openai",
                  case_id="case-1", agent_id="agent-1")
    result.update(changes)
    return result


def test_health_ready_and_auth_matrix():
    with client() as app:
        assert app.get("/health").status_code == 200
        assert app.get("/ready").status_code == 200
        assert app.post("/v1/evaluations", json=payload()).status_code == 401
        assert app.post("/v1/evaluations", json=payload(), headers=AGENT).status_code == 200
        assert app.get("/v1/audit", headers=AGENT).status_code == 403
        assert app.get("/v1/audit", headers=OPERATOR).status_code == 200


def test_evaluation_batch_and_paginated_audit():
    with client() as app:
        single = app.post("/v1/evaluations", json=payload(), headers=AGENT)
        assert single.status_code == 200
        assert single.json()["decision"] == "sanitize"
        assert "alice@example.com" not in str(single.json())
        batch = app.post("/v1/evaluations/batch", json=[payload(), payload("safe")], headers=AGENT)
        assert batch.status_code == 200
        assert [item["decision"] for item in batch.json()["items"]] == ["sanitize", "allow"]
        audit = app.get("/v1/audit?limit=2&offset=0", headers=OPERATOR).json()
        assert audit["total"] == 3 and len(audit["items"]) == 2
        assert "alice@example.com" not in str(audit)


def test_approval_and_policy_activation():
    with client() as app:
        privileged = payload("send alice@example.com", operation="tool_request", destination="privileged:ticket")
        pending = app.post("/v1/evaluations", json=privileged, headers=AGENT).json()
        assert pending["decision"] == "require_approval"
        approval_id = pending["approval_id"]
        assert app.post(f"/v1/approvals/{approval_id}/decision", json={"approve": True}, headers=AGENT).status_code == 403
        assert app.post(f"/v1/approvals/{approval_id}/decision", json={"approve": True}, headers=OPERATOR).status_code == 200
        privileged["approval_id"] = approval_id
        approved = app.post("/v1/evaluations", json=privileged, headers=AGENT).json()
        assert approved["decision"] == "sanitize"
        assert "alice@example.com" not in str(approved)
        current = app.get("/v1/policies", headers=OPERATOR).json()
        assert current["active_policy_hash"]
        assert app.post("/v1/policies/activate", json={"yaml": "not: [valid"}, headers=OPERATOR).status_code == 400
        assert app.get("/v1/policies", headers=OPERATOR).json() == current


def test_bad_input_and_error_response_never_echo_raw_payload():
    with client() as app:
        invalid = payload("alice@example.com", operation="no_such_operation")
        response = app.post("/v1/evaluations", json=invalid, headers=AGENT)
        assert response.status_code == 422
        assert "alice@example.com" not in response.text
        response = app.post("/v1/evaluations", content="{bad alice@example.com", headers={**AGENT, "Content-Type": "application/json"})
        assert response.status_code == 422
        assert "alice@example.com" not in response.text
