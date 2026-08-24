from cognitive_firewall.dashboard.app import sanitize_dashboard_data
from cognitive_firewall.storage.audit import AuditEvent, SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.reports import ReportStore


def test_dashboard_uses_only_aggregate_fields():
    raw = {
        "total": 3,
        "blocked": 1,
        "sanitized": 1,
        "allowed": 1,
        "policy_versions": ["hash"],
        "raw_payload": "alice@example.com",
        "agents": [{"agent_id": "agent-1", "total": 3, "blocked": 1, "raw": "alice@example.com"}],
        "trend": [
            {"hour": 1, "blocked": 1, "mean_injection_score": 40, "raw": "alice@example.com"}
        ],
    }
    safe = sanitize_dashboard_data(raw)
    assert "alice@example.com" not in str(safe)
    assert safe["total"] == 3
    assert safe["agents"][0]["blocked"] == 1
    assert safe["trend"][0]["blocked"] == 1


def test_report_summary_includes_blocked_and_score_trend():
    db = Database("sqlite:///:memory:")
    db.create_all()
    SqlAuditStore(db).record(
        AuditEvent(
            agent_id="agent-1",
            case_id="case-1",
            operation="retrieval",
            decision="block",
            reason_codes=["injection_floor"],
            injection_score=90,
            privacy_score=0,
            policy_hash="hash",
        )
    )
    summary = ReportStore(db).summary()
    assert len(summary["trend"]) == 1
    assert summary["trend"][0]["blocked"] == 1
    assert summary["trend"][0]["mean_injection_score"] == 90
    assert summary["trend"][0]["hour"].endswith(" UTC")
