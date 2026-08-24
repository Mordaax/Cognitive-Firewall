import asyncio

import httpx
import pytest

from cognitive_firewall.schemas import EvaluationRequest, Operation
from cognitive_firewall.sdk.client import AsyncFirewallClient, FirewallClient
from cognitive_firewall.sdk.guard import AgentGuard, EgressDenied


def request():
    return EvaluationRequest(
        operation=Operation.MODEL_INPUT,
        payload="alice@example.com",
        source="user",
        destination="openai",
        case_id="c1",
        agent_id="a1",
    )


def test_sync_client_and_guard_only_emit_safe_payload():
    def firewall_handler(req):
        assert req.headers["authorization"] == "Bearer agent-token"
        return httpx.Response(
            200,
            json={
                "decision": "sanitize",
                "safe_payload": "EMAIL_ABC_01",
                "findings": [],
                "reason_codes": ["internal_privacy"],
                "injection_score": 0,
                "privacy_score": 80,
                "policy_hash": "hash",
                "audit_id": "audit",
            },
        )

    client = FirewallClient(
        "http://firewall", "agent-token", transport=httpx.MockTransport(firewall_handler)
    )
    approved = AgentGuard(client).before_model(request())
    assert approved.content == "EMAIL_ABC_01"
    assert approved.audit_id == "audit"


def test_blocked_or_unavailable_firewall_prevents_egress():
    def blocked(req):
        return httpx.Response(
            200,
            json={
                "decision": "block",
                "safe_payload": None,
                "findings": [],
                "reason_codes": ["secret"],
                "injection_score": 0,
                "privacy_score": 90,
                "policy_hash": "hash",
                "audit_id": "audit",
            },
        )

    guard = AgentGuard(
        FirewallClient("http://firewall", "token", transport=httpx.MockTransport(blocked))
    )
    with pytest.raises(EgressDenied):
        guard.before_model(request())
    guard = AgentGuard(
        FirewallClient(
            "http://firewall",
            "token",
            transport=httpx.MockTransport(lambda req: httpx.Response(503)),
        )
    )
    with pytest.raises(EgressDenied):
        guard.before_model(request())


def test_client_refuses_remote_firewall_for_raw_content():
    with pytest.raises(ValueError):
        FirewallClient("https://remote.example", "token")


def test_async_client_uses_same_contract():
    async def handler(req):
        return httpx.Response(
            200,
            json={
                "decision": "allow",
                "safe_payload": "safe",
                "findings": [],
                "reason_codes": ["default_allow"],
                "injection_score": 0,
                "privacy_score": 0,
                "policy_hash": "hash",
                "audit_id": "audit",
            },
        )

    async def run():
        async with AsyncFirewallClient(
            "http://firewall", "token", transport=httpx.MockTransport(handler)
        ) as client:
            assert (await client.evaluate(request())).safe_payload == "safe"

    asyncio.run(run())
