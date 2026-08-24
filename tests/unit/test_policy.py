from pathlib import Path

import pytest

from cognitive_firewall.policy.evaluator import evaluate_policy
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Finding, Operation

POLICY = Path("policies/default.yaml")


def request(operation=Operation.MODEL_INPUT, destination="openai"):
    return EvaluationRequest(
        operation=operation,
        payload="alice@example.com",
        source="user",
        destination=destination,
        case_id="case-1",
        agent_id="agent-1",
    )


def finding(category, severity=65):
    return Finding(
        category=category, severity=severity, reason_code=f"test_{category}", start=0, end=5
    )


def test_internal_analysis_pseudonymizes_and_export_redacts():
    policy = load_policy(POLICY)
    internal = evaluate_policy(request(), [finding("email")], policy)
    exported = evaluate_policy(request(Operation.EXPORT, "external"), [finding("email")], policy)
    assert internal.action == DecisionAction.SANITIZE
    assert internal.transformations["email"] == "pseudonymize"
    assert exported.transformations["email"] == "redact"
    assert policy.policy_hash


def test_secret_and_high_risk_injection_block_before_sanitization():
    policy = load_policy(POLICY)
    assert (
        evaluate_policy(request(), [finding("email"), finding("secret", 100)], policy).action
        == DecisionAction.BLOCK
    )
    assert (
        evaluate_policy(request(Operation.RETRIEVAL), [finding("injection", 90)], policy).action
        == DecisionAction.BLOCK
    )


def test_privileged_tool_requires_approval_and_invalid_policy_fails(tmp_path):
    policy = load_policy(POLICY)
    outcome = evaluate_policy(request(Operation.TOOL_REQUEST, "privileged:delete"), [], policy)
    assert outcome.action == DecisionAction.REQUIRE_APPROVAL
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrules: [oops", encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(bad)
