import pytest

from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy_bytes
from cognitive_firewall.schemas import EvaluationRequest, Operation
from cognitive_firewall.sdk.guard import AgentGuard, ApprovedPayload, EgressDenied
from cognitive_firewall.sdk.providers import ClaudeAdapter, OpenAIAdapter
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore


@pytest.mark.parametrize("adapter", [OpenAIAdapter, ClaudeAdapter])
def test_provider_adapter_rejects_raw_and_sends_only_approved_content(adapter):
    captured = []
    provider = adapter(transport=lambda content: captured.append(content) or {"ok": True})
    with pytest.raises(TypeError):
        provider.send("alice@example.com")
    assert captured == []
    with pytest.raises(TypeError):
        ApprovedPayload("alice@example.com", "audit")
    payload = ApprovedPayload._from_decision(
        "EMAIL_ABC_01",
        "audit",
        "hash",
        operation=Operation.MODEL_INPUT,
        destination="openai" if adapter is OpenAIAdapter else "claude",
    )
    with pytest.raises(AttributeError):
        payload.content = "alice@example.com"
    assert provider.send(payload) == {"ok": True}
    assert captured == ["EMAIL_ABC_01"]


@pytest.mark.parametrize("adapter", [OpenAIAdapter, ClaudeAdapter])
def test_approved_object_cannot_be_changed_after_issuance(adapter):
    original = {"message": ["EMAIL_ABC_01"]}
    approved = ApprovedPayload._from_decision(
        original,
        "audit",
        "hash",
        operation=Operation.MODEL_INPUT,
        destination="openai" if adapter is OpenAIAdapter else "claude",
    )
    original["message"].append("alice@example.com")
    approved.content["message"].append("bob@example.com")
    captured = []
    adapter(transport=lambda content: captured.append(content)).send(approved)
    assert captured == ['{"message": ["EMAIL_ABC_01"]}']


@pytest.mark.parametrize("adapter", [OpenAIAdapter, ClaudeAdapter])
def test_provider_capture_excludes_pii_even_with_permissive_policy(adapter):
    db = Database("sqlite:///:memory:")
    db.create_all()
    policy = load_policy_bytes(
        b"version: 2\nrules:\n  - id: permissive\n    priority: 1\n    action: allow\n"
    )
    engine = Evaluator(
        policy,
        SqlAuditStore(db),
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
    )
    guard = AgentGuard(engine)
    captured = []
    provider = adapter(transport=lambda content: captured.append(content))
    request = EvaluationRequest(
        operation=Operation.MODEL_INPUT,
        payload="alice@example.com",
        source="user",
        destination="openai" if adapter is OpenAIAdapter else "claude",
        case_id="case-1",
        agent_id="agent-1",
    )
    provider.send(guard.before_model(request))
    assert captured and "alice@example.com" not in captured[0]
    with pytest.raises(EgressDenied):
        provider.send(
            guard.before_model(request.model_copy(update={"payload": {"phone": 6505551234}}))
        )
    assert len(captured) == 1


def test_provider_requires_model_input_approval_for_its_destination():
    db = Database("sqlite:///:memory:")
    db.create_all()
    engine = Evaluator(
        load_policy_bytes(
            b"version: 2\nrules:\n  - id: allow\n    priority: 1\n    action: allow\n"
        ),
        SqlAuditStore(db),
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
    )
    guard = AgentGuard(engine)
    captured = []
    provider = OpenAIAdapter(transport=lambda value: captured.append(value))
    base = EvaluationRequest(
        operation=Operation.MODEL_INPUT,
        payload="safe",
        source="user",
        destination="openai",
        case_id="case-1",
        agent_id="agent-1",
    )
    with pytest.raises(EgressDenied):
        provider.send(guard.after_retrieval(base))
    with pytest.raises(EgressDenied):
        provider.send(guard.before_model(base.model_copy(update={"destination": "claude"})))
    assert captured == []
