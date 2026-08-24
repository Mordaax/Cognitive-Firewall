import pytest

from cognitive_firewall.sdk.guard import ApprovedPayload
from cognitive_firewall.sdk.providers import ClaudeAdapter, OpenAIAdapter


@pytest.mark.parametrize("adapter", [OpenAIAdapter, ClaudeAdapter])
def test_provider_adapter_rejects_raw_and_sends_only_approved_content(adapter):
    captured = []
    provider = adapter(transport=lambda content: captured.append(content) or {"ok": True})
    with pytest.raises(TypeError):
        provider.send("alice@example.com")
    assert captured == []
    with pytest.raises(TypeError):
        ApprovedPayload("alice@example.com", "audit")
    payload = ApprovedPayload._from_decision("EMAIL_ABC_01", "audit", "hash")
    with pytest.raises(AttributeError):
        payload.content = "alice@example.com"
    assert provider.send(payload) == {"ok": True}
    assert captured == ["EMAIL_ABC_01"]
