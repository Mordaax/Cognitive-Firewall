from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cognitive_firewall.api.auth import Authenticator
from cognitive_firewall.config import Settings
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Operation, Provenance
from cognitive_firewall.storage.approvals import ApprovalBinding, ApprovalStore
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore


def setup():
    db = Database("sqlite:///:memory:")
    db.create_all()
    audit = SqlAuditStore(db)
    approvals = ApprovalStore(db, audit)
    engine = Evaluator(
        load_policy(Path("policies/default.yaml")),
        audit,
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
        approval_store=approvals,
    )
    return engine, approvals


def request(payload="send alice@example.com", **kwargs):
    values = dict(
        operation=Operation.TOOL_REQUEST,
        payload=payload,
        source="agent",
        destination="privileged:ticket",
        case_id="case-1",
        agent_id="agent-1",
    )
    values.update(kwargs)
    return EvaluationRequest(**values)


def test_authentication_separates_agent_and_operator_roles():
    settings = Settings("agent-secret", "operator-secret", "mapping", "hmac")
    auth = Authenticator(settings)
    assert auth.require_role("Bearer agent-secret", "agent").role == "agent"
    assert auth.require_role("Bearer operator-secret", "operator").role == "operator"
    with pytest.raises(PermissionError):
        auth.require_role("Bearer agent-secret", "operator")
    with pytest.raises(PermissionError):
        auth.require_role("Bearer invalid", "agent")
    with pytest.raises(PermissionError):
        auth.require_role("", "agent")


def test_approval_binding_is_exact_single_use_and_expires():
    _, approvals = setup()
    now = datetime.now(timezone.utc)
    original = ApprovalBinding.from_request(request(), "policy-1")
    approval_id = approvals.create(original, now + timedelta(minutes=5))
    assert approvals.decide(approval_id, approve=True)
    assert not approvals.consume(
        approval_id, ApprovalBinding.from_request(request("changed"), "policy-1"), now
    )
    assert not approvals.consume(
        approval_id, ApprovalBinding.from_request(request(case_id="case-2"), "policy-1"), now
    )
    assert not approvals.consume(
        approval_id, ApprovalBinding.from_request(request(), "policy-2"), now
    )
    assert not approvals.consume(
        approval_id,
        ApprovalBinding.from_request(request(provenance=Provenance(source_id="other")), "policy-1"),
        now,
    )
    assert approvals.consume(approval_id, original, now)
    assert not approvals.consume(approval_id, original, now)
    expired = approvals.create(original, now - timedelta(seconds=1))
    assert not approvals.decide(expired, approve=True)
    assert not approvals.consume(expired, original, now)


def test_audit_failure_cannot_leave_approval_granted():
    _, approvals = setup()
    binding = ApprovalBinding.from_request(request(), "policy-1")
    approval_id = approvals.create(binding, datetime.now(timezone.utc) + timedelta(minutes=5))
    original_audit = approvals.audit

    class FailedAudit:
        def record_in_session(self, session, event):
            raise OSError("audit unavailable")

    approvals.audit = FailedAudit()
    with pytest.raises(OSError):
        approvals.decide(approval_id, approve=True)
    approvals.audit = original_audit
    assert not approvals.consume(approval_id, binding, datetime.now(timezone.utc))
    assert approvals.decide(approval_id, approve=True)


def test_evaluator_requires_operator_decision_then_sanitizes_exact_resubmission():
    engine, approvals = setup()
    pending = engine.evaluate(request())
    assert pending.decision == DecisionAction.REQUIRE_APPROVAL
    assert pending.approval_id and pending.safe_payload is None
    assert approvals.decide(pending.approval_id, approve=True)
    rejected_change = engine.evaluate(request("changed", approval_id=pending.approval_id))
    assert rejected_change.decision == DecisionAction.BLOCK
    approved = engine.evaluate(request(approval_id=pending.approval_id))
    assert approved.decision == DecisionAction.SANITIZE
    assert approved.safe_payload and "alice@example.com" not in str(approved.safe_payload)
    assert (
        engine.evaluate(request(approval_id=pending.approval_id)).decision == DecisionAction.BLOCK
    )
