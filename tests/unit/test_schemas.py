import pytest
from pydantic import ValidationError

from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, EvaluationResponse, Operation


def test_request_rejects_missing_case_id_and_oversized_payload():
    base = dict(operation=Operation.MODEL_INPUT, payload="safe", source="user", destination="openai", agent_id="agent-1")
    with pytest.raises(ValidationError):
        EvaluationRequest(**base)
    with pytest.raises(ValidationError):
        EvaluationRequest(**{**base, "case_id": "case-1", "payload": "x" * 65_537})


def test_blocked_response_never_serializes_raw_payload():
    response = EvaluationResponse(
        decision=DecisionAction.BLOCK,
        safe_payload=None,
        findings=[],
        reason_codes=["secret_detected"],
        injection_score=0,
        privacy_score=100,
        policy_hash="abc",
        audit_id="event-1",
    )
    assert "private@example.com" not in response.model_dump_json()
    assert response.safe_payload is None
