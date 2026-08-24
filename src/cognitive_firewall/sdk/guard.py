"""Approved payload capability from a successful firewall decision."""

from __future__ import annotations

import json

from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Operation
from cognitive_firewall.sdk.client import FirewallUnavailable

_CAPABILITY = object()


class EgressDenied(RuntimeError):
    pass


class ApprovedPayload:
    __slots__ = ("_wire_content", "_is_text", "audit_id", "policy_hash", "operation", "destination")
    _wire_content: str
    _is_text: bool
    audit_id: str
    policy_hash: str
    operation: Operation
    destination: str

    def __init__(
        self,
        content: str | dict,
        audit_id: str,
        policy_hash: str = "",
        *,
        operation: Operation | None = None,
        destination: str = "",
        _key: object = None,
    ):
        if (
            _key is not _CAPABILITY
            or not audit_id
            or content is None
            or operation is None
            or not destination
        ):
            raise TypeError("approved payloads are issued only after an allow or sanitize decision")
        is_text = isinstance(content, str)
        snapshot = content if is_text else json.dumps(content, ensure_ascii=False)
        object.__setattr__(self, "_wire_content", snapshot)
        object.__setattr__(self, "_is_text", is_text)
        object.__setattr__(self, "audit_id", audit_id)
        object.__setattr__(self, "policy_hash", policy_hash)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "destination", destination)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("approved payloads are immutable")

    @property
    def content(self) -> str | dict:
        return self._wire_content if self._is_text else json.loads(self._wire_content)

    @classmethod
    def _from_decision(
        cls,
        content: str | dict,
        audit_id: str,
        policy_hash: str,
        *,
        operation: Operation,
        destination: str,
    ) -> "ApprovedPayload":
        return cls(
            content,
            audit_id,
            policy_hash,
            operation=operation,
            destination=destination,
            _key=_CAPABILITY,
        )


class AgentGuard:
    def __init__(self, client):
        self.client = client

    def _at(self, request: EvaluationRequest, operation: Operation) -> ApprovedPayload:
        try:
            result = self.client.evaluate(request.model_copy(update={"operation": operation}))
        except FirewallUnavailable as exc:
            raise EgressDenied("firewall unavailable") from exc
        if (
            result.decision not in {DecisionAction.ALLOW, DecisionAction.SANITIZE}
            or result.safe_payload is None
        ):
            raise EgressDenied("firewall denied operation")
        return ApprovedPayload._from_decision(
            result.safe_payload,
            result.audit_id,
            result.policy_hash,
            operation=operation,
            destination=request.destination,
        )

    def before_model(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.MODEL_INPUT)

    def after_retrieval(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.RETRIEVAL)

    def before_tool(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.TOOL_REQUEST)

    def after_tool(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.TOOL_RESULT)

    def before_memory_write(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.MEMORY_WRITE)

    def after_memory_read(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.MEMORY_READ)

    def after_model(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.MODEL_OUTPUT)

    def before_export(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.EXPORT)
