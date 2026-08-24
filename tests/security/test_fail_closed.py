from pathlib import Path

from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Operation


class FailedAudit:
    def record(self, event):
        raise OSError("audit storage unavailable")


class NoMapping:
    def get_or_create(self, *args):
        raise OSError("mapping storage unavailable")


def test_audit_or_mapping_failure_blocks_without_payload_echo():
    service = Evaluator(load_policy(Path("policies/default.yaml")), FailedAudit(), NoMapping())
    request = EvaluationRequest(operation=Operation.MODEL_INPUT, payload="alice@example.com", source="user", destination="openai", case_id="c1", agent_id="a1")
    response = service.evaluate(request)
    assert response.decision == DecisionAction.BLOCK
    assert response.safe_payload is None
    assert "alice@example.com" not in response.model_dump_json()


def test_detector_failure_blocks(monkeypatch):
    from cognitive_firewall import engine
    monkeypatch.setattr(engine, "detect_pii", lambda payload: (_ for _ in ()).throw(RuntimeError("detector broke")))
    service = Evaluator(load_policy(Path("policies/default.yaml")), FailedAudit(), NoMapping())
    request = EvaluationRequest(operation=Operation.MODEL_INPUT, payload="hello", source="user", destination="openai", case_id="c1", agent_id="a1")
    response = service.evaluate(request)
    assert response.decision == DecisionAction.BLOCK
    assert response.reason_codes == ["evaluation_unavailable"]
