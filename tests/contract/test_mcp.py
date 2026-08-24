import asyncio
from pathlib import Path

from mcp import Client

from cognitive_firewall.engine import Evaluator
from cognitive_firewall.mcp.server import build_mcp_server
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import EvaluationRequest, Operation
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore


def test_mcp_evaluation_matches_engine_contract():
    db = Database("sqlite:///:memory:")
    db.create_all()
    engine = Evaluator(
        load_policy(Path("policies/default.yaml")),
        SqlAuditStore(db),
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
    )
    server = build_mcp_server(engine)
    request = EvaluationRequest(
        operation=Operation.MODEL_INPUT,
        payload="alice@example.com",
        source="user",
        destination="openai",
        case_id="c1",
        agent_id="demo-agent",
    )

    async def run():
        async with Client(server) as client:
            tools = await client.list_tools()
            names = [tool.name for tool in tools.tools]
            assert "evaluate_content" in names and "sanitize_content" in names
            result = await client.call_tool(
                "evaluate_content", {"request": request.model_dump(mode="json")}
            )
            assert not result.is_error, str(result.content)
            assert result.structured_content["decision"] == "sanitize"
            assert "alice@example.com" not in str(result.structured_content)

    asyncio.run(run())
