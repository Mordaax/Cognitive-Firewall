from pathlib import Path

from fastapi.testclient import TestClient

from cognitive_firewall.api.app import create_app
from cognitive_firewall.config import Settings
from cognitive_firewall.schemas import EvaluationRequest
from examples.langgraph_agent import _mock_engine


def action(**changes):
    values = dict(operation="tool_request", payload={"action": "delete_all_reports"},
                  source="agent", destination="tool:files", case_id="case-1",
                  agent_id="demo-agent")
    values.update(changes)
    return EvaluationRequest(**values)


def test_unknown_tool_is_blocked_even_when_content_has_no_attack_phrase():
    result = _mock_engine().evaluate(action())
    assert result.decision == "block"
    assert result.safe_payload is None


def test_api_cannot_impersonate_another_agent():
    settings = Settings("agent-secret", "operator-secret", "e" * 32, "h" * 32,
                        database_url="sqlite:///:memory:")
    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/evaluations", headers={"Authorization": "Bearer agent-secret"},
                               json=action(operation="model_input", payload="ordinary",
                                           destination="openai", agent_id="impersonator").model_dump())
    assert response.status_code == 403


def test_resource_permissions_and_schema_are_independent_of_prompt_text(tmp_path):
    from cognitive_firewall.security.tools import ToolRegistry

    registry = ToolRegistry.from_dict({"tools": {
        "tool:read": {"agents": ["demo-agent"], "read_only": True, "input_schema": {
            "type": "object", "properties": {"path": {"type": "string"}},
            "required": ["path"], "additionalProperties": False},
            "path_fields": {"path": [str(tmp_path)]}},
        "tool:send": {"agents": ["demo-agent"], "input_schema": {
            "type": "object", "properties": {"recipient": {"type": "string"}},
            "required": ["recipient"], "additionalProperties": False},
            "recipient_fields": {"recipient": ["approved@example.com"]}},
    }})
    assert registry.check(action(destination="tool:read", payload={"path": str(tmp_path / "ok")})) is False
    for request in [
        action(destination="tool:read", payload={"path": str(tmp_path / "../outside")}),
        action(destination="tool:read", payload={"path": str(tmp_path), "extra": "unexpected"}),
        action(destination="tool:read", payload={"path": str(tmp_path)}, agent_id="other-agent"),
        action(destination="tool:send", payload={"recipient": "unapproved@example.com"}),
        action(destination="tool:missing", payload={}),
    ]:
        import pytest
        with pytest.raises(PermissionError):
            registry.check(request)


def test_url_permissions_reject_credentials_private_literals_and_unlisted_hosts():
    import pytest

    from cognitive_firewall.security.tools import ToolRegistry

    registry = ToolRegistry.from_dict({"tools": {"tool:fetch": {
        "agents": ["demo-agent"], "read_only": True, "input_schema": {"type": "object",
            "properties": {"url": {"type": "string"}}, "required": ["url"],
            "additionalProperties": False}, "host_fields": {"url": ["example.com", "127.0.0.1"]}
    }}})
    assert registry.check(action(destination="tool:fetch", payload={"url": "https://example.com/a"})) is False
    for url in ["http://example.com", "https://example.com.evil.invalid", "https://127.0.0.1/",
                "https://user:pass@example.com/", "https://example.com:8443/", "file:///secrets"]:
        with pytest.raises(PermissionError):
            registry.check(action(destination="tool:fetch", payload={"url": url}))


def test_external_schema_references_are_rejected_without_network_access():
    import pytest

    from cognitive_firewall.security.tools import ToolRegistry

    with pytest.raises(ValueError):
        ToolRegistry.from_dict({"tools": {"tool:bad": {
            "agents": ["demo-agent"], "input_schema": {"type": "object",
                "$ref": "https://example.invalid/schema", "additionalProperties": False}
        }}})


def test_relative_paths_are_denied_even_if_server_cwd_is_inside_allowed_root():

    import pytest

    from cognitive_firewall.security.tools import ToolRegistry

    registry = ToolRegistry.from_dict({"tools": {"tool:read": {
        "agents": ["demo-agent"], "read_only": True,
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                         "required": ["path"], "additionalProperties": False},
        "path_fields": {"path": [str(Path.cwd())]},
    }}})
    for path in ["secrets.txt", "./secrets.txt", "C:secrets.txt", "\\secrets.txt"]:
        with pytest.raises(PermissionError):
            registry.check(action(destination="tool:read", payload={"path": path}))
