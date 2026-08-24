from fastapi.testclient import TestClient

from cognitive_firewall.api.app import create_app
from cognitive_firewall.config import Settings

AGENT = {"Authorization": "Bearer agent-secret"}
OPERATOR = {"Authorization": "Bearer operator-secret"}


def client():
    settings = Settings(
        "agent-secret",
        "operator-secret",
        "e" * 32,
        "h" * 32,
        database_url="sqlite:///:memory:",
        policy_path="policies/default.yaml",
    )
    return TestClient(create_app(settings))


def payload(text="alice@example.com", **changes):
    result = dict(
        operation="model_input",
        payload=text,
        source="user",
        destination="openai",
        case_id="case-1",
        agent_id="demo-agent",
    )
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
        privileged = payload(
            {"service": "demo"}, operation="tool_request", destination="privileged:restart"
        )
        pending = app.post("/v1/evaluations", json=privileged, headers=AGENT).json()
        assert pending["decision"] == "require_approval"
        approval_id = pending["approval_id"]
        assert app.get(f"/v1/approvals/{approval_id}", headers=AGENT).status_code == 403
        review = app.get(f"/v1/approvals/{approval_id}", headers=OPERATOR)
        assert review.status_code == 200
        assert review.json()["operation"] == "tool_request"
        assert review.json()["destination"] == "privileged:restart"
        assert review.json()["agent_id"] == "demo-agent"
        assert "alice@example.com" not in review.text
        listing = app.get("/v1/approvals/pending", headers=OPERATOR)
        assert listing.status_code == 200
        assert any(item["id"] == approval_id for item in listing.json()["items"])
        assert (
            app.post(
                f"/v1/approvals/{approval_id}/decision", json={"approve": True}, headers=AGENT
            ).status_code
            == 403
        )
        assert (
            app.post(
                f"/v1/approvals/{approval_id}/decision", json={"approve": True}, headers=OPERATOR
            ).status_code
            == 200
        )
        privileged["approval_id"] = approval_id
        approved = app.post("/v1/evaluations", json=privileged, headers=AGENT).json()
        assert approved["decision"] == "allow"
        assert "alice@example.com" not in str(approved)
        current = app.get("/v1/policies", headers=OPERATOR).json()
        assert current["active_policy_hash"]
        assert (
            app.post(
                "/v1/policies/activate", json={"yaml": "not: [valid"}, headers=OPERATOR
            ).status_code
            == 400
        )
        assert app.get("/v1/policies", headers=OPERATOR).json() == current


def test_bad_input_and_error_response_never_echo_raw_payload():
    with client() as app:
        invalid = payload("alice@example.com", operation="no_such_operation")
        response = app.post("/v1/evaluations", json=invalid, headers=AGENT)
        assert response.status_code == 422
        assert "alice@example.com" not in response.text
        response = app.post(
            "/v1/evaluations",
            content="{bad alice@example.com",
            headers={**AGENT, "Content-Type": "application/json"},
        )
        assert response.status_code == 422
        assert "alice@example.com" not in response.text


def test_reidentification_requires_operator_and_is_audited():
    with client() as app:
        result = app.post("/v1/evaluations", json=payload(), headers=AGENT).json()
        token = result["safe_payload"]
        body = {"case_id": "case-1", "token": token}
        assert app.post("/v1/mappings/reidentify", json=body, headers=AGENT).status_code == 403
        assert app.post("/v1/mappings/reidentify", json=body, headers=OPERATOR).status_code != 200
        pending = app.post("/v1/mappings/reidentify/request", json=body, headers=OPERATOR)
        assert pending.status_code == 200
        approval_id = pending.json()["approval_id"]
        assert (
            app.post(
                "/v1/mappings/reidentify",
                json={**body, "approval_id": approval_id},
                headers=OPERATOR,
            ).status_code
            != 200
        )
        assert (
            app.post(
                f"/v1/approvals/{approval_id}/decision", json={"approve": True}, headers=OPERATOR
            ).status_code
            == 200
        )
        resolved = app.post(
            "/v1/mappings/reidentify", json={**body, "approval_id": approval_id}, headers=OPERATOR
        )
        assert resolved.status_code == 200 and resolved.json()["value"] == "alice@example.com"
        assert (
            app.post(
                "/v1/mappings/reidentify",
                json={**body, "approval_id": approval_id},
                headers=OPERATOR,
            ).status_code
            != 200
        )
        audit = app.get("/v1/audit", headers=OPERATOR).json()
        assert any("mapping_reidentified" in row["reason_codes"] for row in audit["items"])
        assert "alice@example.com" not in str(audit)


def test_sensitive_metadata_is_rejected_without_echo():
    with client() as app:
        request = payload()
        request["agent_id"] = "alice@example.com"
        response = app.post("/v1/evaluations", json=request, headers=AGENT)
        assert response.status_code == 422
        assert "alice@example.com" not in response.text
        request = payload()
        request["provenance"] = {"source_id": "sk-" + "a" * 32}
        response = app.post("/v1/evaluations", json=request, headers=AGENT)
        assert response.status_code == 422


def test_activated_policy_survives_restart(tmp_path):
    settings = Settings(
        "agent-secret",
        "operator-secret",
        "e" * 32,
        "h" * 32,
        database_url=f"sqlite:///{(tmp_path / 'policy.db').as_posix()}",
        policy_path="policies/default.yaml",
    )
    policy_yaml = (
        __import__("pathlib")
        .Path("policies/default.yaml")
        .read_text()
        .replace(
            "  - id: default_allow\n    priority: 1\n    action: allow",
            "  - id: default_allow\n    priority: 1\n    action: block",
        )
    )
    with TestClient(create_app(settings)) as app:
        result = app.post("/v1/policies/activate", json={"yaml": policy_yaml}, headers=OPERATOR)
        assert result.status_code == 200
        expected_hash = result.json()["active_policy_hash"]
    with TestClient(create_app(settings)) as app:
        assert (
            app.get("/v1/policies", headers=OPERATOR).json()["active_policy_hash"] == expected_hash
        )
        assert (
            app.post("/v1/evaluations", json=payload("safe"), headers=AGENT).json()["decision"]
            == "block"
        )


def test_running_process_uses_new_active_policy(tmp_path):
    settings = Settings(
        "agent-secret",
        "operator-secret",
        "e" * 32,
        "h" * 32,
        database_url=f"sqlite:///{(tmp_path / 'shared.db').as_posix()}",
        policy_path="policies/default.yaml",
    )
    replacement = "version: 2\nrules:\n  - id: deny_all\n    priority: 1\n    action: block\n"
    with TestClient(create_app(settings)) as first, TestClient(create_app(settings)) as second:
        prior = second.post("/v1/evaluations", json=payload("ordinary"), headers=AGENT).json()
        assert prior["decision"] == "allow"
        activated = first.post(
            "/v1/policies/activate", json={"yaml": replacement}, headers=OPERATOR
        )
        assert activated.status_code == 200
        current = second.post("/v1/evaluations", json=payload("ordinary"), headers=AGENT).json()
        assert current["decision"] == "block"
        assert current["policy_hash"] == activated.json()["active_policy_hash"]
