from cognitive_firewall.dashboard.app import sanitize_dashboard_data


def test_dashboard_uses_only_aggregate_fields():
    raw = {
        "total": 3,
        "blocked": 1,
        "sanitized": 1,
        "allowed": 1,
        "policy_versions": ["hash"],
        "raw_payload": "alice@example.com",
        "agents": [{"agent_id": "agent-1", "total": 3, "blocked": 1, "raw": "alice@example.com"}],
    }
    safe = sanitize_dashboard_data(raw)
    assert "alice@example.com" not in str(safe)
    assert safe["total"] == 3
    assert safe["agents"][0]["blocked"] == 1
