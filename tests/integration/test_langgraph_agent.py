import json
from pathlib import Path

from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.security.provenance import ProvenanceStore
from cognitive_firewall.security.tools import ToolRegistry
from cognitive_firewall.storage.approvals import ApprovalStore
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore
from cognitive_firewall.storage.memory import SqlMemoryStore
from examples.langgraph_agent import run_demo


def test_langgraph_workflow_checks_all_boundaries_and_keeps_model_egress_safe():
    db = Database("sqlite:///:memory:")
    db.create_all()
    engine = Evaluator(
        load_policy(Path("policies/default.yaml")),
        SqlAuditStore(db),
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
        SqlMemoryStore(db),
        approval_store=ApprovalStore(db),
        tool_registry=ToolRegistry.from_file(Path("policies/tools.yaml")),
        provenance_store=ProvenanceStore(db),
    )
    fixture = json.loads(Path("examples/data/synthetic_incident.json").read_text())
    captured = []
    result = run_demo(
        fixture,
        evaluator=engine,
        provider="mock",
        model_transport=lambda value: captured.append(value) or "Resolved.",
    )
    assert result["steps"] == [
        "retrieval",
        "model_input",
        "tool_request",
        "tool_result",
        "memory_write",
        "memory_read",
        "model_output",
        "export",
    ]
    assert result["decisions"]["retrieval"] == "block"
    assert result["decisions"]["tool_result"] == "block"
    assert result["decisions"]["memory_write"] == "require_approval"
    assert result["decisions"]["tool_request"] == "require_approval"
    assert not result["memory_id"]
    assert captured and "alice@example.com" not in str(captured)
    assert "CUST-123456" not in str(captured)
    assert "alice@example.com" not in str(result)
