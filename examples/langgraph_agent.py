"""Synthetic LangGraph workflow with every firewall boundary represented."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import EvaluationRequest, Operation
from cognitive_firewall.sdk.guard import AgentGuard, EgressDenied
from cognitive_firewall.sdk.providers import ClaudeAdapter, OpenAIAdapter
from cognitive_firewall.security.provenance import ProvenanceStore
from cognitive_firewall.security.tools import ToolRegistry
from cognitive_firewall.storage.approvals import ApprovalStore
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore
from cognitive_firewall.storage.memory import SqlMemoryStore


class DemoState(TypedDict, total=False):
    safe_retrieval: str
    model_output: str
    safe_tool_request: str
    safe_tool_result: str
    memory_id: str
    safe_memory: str
    safe_export: str
    steps: list[str]
    decisions: dict[str, str]
    audit_ids: list[str]


class TrackedClient:
    def __init__(self, evaluator: Evaluator):
        self.evaluator = evaluator
        self.last = None

    def evaluate(self, request: EvaluationRequest):
        self.last = self.evaluator.evaluate(request)
        return self.last


def _mock_engine() -> Evaluator:
    db = Database("sqlite:///:memory:")
    db.create_all()
    audit = SqlAuditStore(db)
    return Evaluator(
        load_policy(Path(__file__).resolve().parents[1] / "policies/default.yaml"),
        audit,
        SqlMappingStore(db, encryption_key=os.urandom(32), hmac_key=os.urandom(32)),
        SqlMemoryStore(db),
        approval_store=ApprovalStore(db, audit),
        tool_registry=ToolRegistry.from_file(Path(__file__).resolve().parents[1] / "policies/tools.yaml"),
        provenance_store=ProvenanceStore(db),
    )


def run_demo(
    fixture: dict,
    *,
    evaluator: Evaluator | None = None,
    provider: str = "mock",
    model_transport: Callable[[str], Any] | None = None,
) -> dict:
    evaluator = evaluator or _mock_engine()
    tracked = TrackedClient(evaluator)
    guard = AgentGuard(tracked)
    if provider == "openai":
        adapter = OpenAIAdapter(
            transport=model_transport, model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        )
    elif provider == "claude":
        adapter = ClaudeAdapter(
            transport=model_transport, model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
        )
    elif provider == "mock":
        adapter = OpenAIAdapter(transport=model_transport or (lambda _: "Resolved."))
    else:
        raise ValueError("unsupported provider")

    def request(
        operation: Operation, content: str, source: str, destination: str
    ) -> EvaluationRequest:
        return EvaluationRequest(
            operation=operation,
            payload=content,
            source=source,
            destination=destination,
            case_id=fixture["case_id"],
            agent_id=fixture["agent_id"],
        )

    def update(
        state: DemoState,
        operation: Operation,
        action: Callable,
        content: str,
        source: str,
        destination: str,
    ) -> tuple[object | None, dict]:
        try:
            approved = action(request(operation, content, source, destination))
        except EgressDenied:
            approved = None
        decision = tracked.last.decision.value if tracked.last else "block"
        return approved, {
            "steps": state.get("steps", []) + [operation.value],
            "decisions": {**state.get("decisions", {}), operation.value: decision},
            "audit_ids": state.get("audit_ids", [])
            + ([tracked.last.audit_id] if tracked.last and tracked.last.audit_id else []),
        }

    def retrieval(state: DemoState) -> DemoState:
        approved, meta = update(
            state,
            Operation.RETRIEVAL,
            guard.after_retrieval,
            fixture["retrieved_text"],
            "retrieval",
            "model",
        )
        return {
            **meta,
            "safe_retrieval": str(approved.content) if approved else "[retrieval blocked]",
        }

    def model(state: DemoState) -> DemoState:
        approved, meta = update(
            state,
            Operation.MODEL_INPUT,
            guard.before_model,
            fixture["user_input"] + "\n" + state["safe_retrieval"],
            "user",
            "openai" if provider == "mock" else provider,
        )
        if approved is None:
            return {**meta, "model_output": "[model input blocked]"}
        response = adapter.send(approved)
        if provider == "mock" or model_transport is not None:
            model_output = str(response)
        elif provider == "openai":
            model_output = response.output_text
        else:
            model_output = "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            )
        return {**meta, "model_output": model_output}

    def tool_request(state: DemoState) -> DemoState:
        approved, meta = update(
            state,
            Operation.TOOL_REQUEST,
            guard.before_tool,
            {"query": "lookup synthetic ticket"},
            "agent",
            "tool:ticket",
        )
        return {
            **meta,
            "safe_tool_request": str(approved.content) if approved else "[tool request blocked]",
        }

    def tool_result(state: DemoState) -> DemoState:
        approved, meta = update(
            state, Operation.TOOL_RESULT, guard.after_tool, fixture["tool_result"], "tool", "model"
        )
        return {
            **meta,
            "safe_tool_result": str(approved.content) if approved else "[tool result blocked]",
        }

    def memory_write(state: DemoState) -> DemoState:
        content = state["model_output"] + " Contact alice@example.com."
        approved, meta = update(
            state, Operation.MEMORY_WRITE, guard.before_memory_write, content, "agent", "memory"
        )
        return {**meta, "memory_id": tracked.last.memory_id or "" if approved else ""}

    def memory_read(state: DemoState) -> DemoState:
        record = evaluator.memory_store.read(state["memory_id"]) if state.get("memory_id") else None
        content = str(record.content) if record else "[memory unavailable]"
        approved, meta = update(
            state, Operation.MEMORY_READ, guard.after_memory_read, content, "memory", "model"
        )
        return {**meta, "safe_memory": str(approved.content) if approved else "[memory blocked]"}

    def model_output(state: DemoState) -> DemoState:
        approved, meta = update(
            state,
            Operation.MODEL_OUTPUT,
            guard.after_model,
            state["model_output"],
            provider,
            "user",
        )
        return {**meta, "model_output": str(approved.content) if approved else "[output blocked]"}

    def export(state: DemoState) -> DemoState:
        approved, meta = update(
            state,
            Operation.EXPORT,
            guard.before_export,
            state["model_output"] + " " + state["safe_memory"],
            "agent",
            "file",
        )
        return {**meta, "safe_export": str(approved.content) if approved else "[export blocked]"}

    graph = StateGraph(DemoState)
    nodes = [
        ("retrieval", retrieval),
        ("model", model),
        ("tool_request", tool_request),
        ("tool_result", tool_result),
        ("memory_write", memory_write),
        ("memory_read", memory_read),
        ("model_output", model_output),
        ("export", export),
    ]
    for name, function in nodes:
        graph.add_node(name, function)
    graph.add_edge(START, nodes[0][0])
    for (current, _), (following, _) in zip(nodes, nodes[1:]):
        graph.add_edge(current, following)
    graph.add_edge(nodes[-1][0], END)
    final = graph.compile().invoke({"steps": [], "decisions": {}, "audit_ids": []})
    return {
        key: final[key] for key in ("steps", "decisions", "audit_ids", "memory_id", "safe_export")
    }


def main() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
    except ImportError:
        pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["mock", "openai", "claude"], default="mock")
    parser.add_argument(
        "--fixture", type=Path, default=Path(__file__).parent / "data/synthetic_incident.json"
    )
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    result = run_demo(fixture, provider=args.provider)
    print(
        json.dumps(
            {
                "steps": result["steps"],
                "decisions": result["decisions"],
                "audit_ids": result["audit_ids"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
