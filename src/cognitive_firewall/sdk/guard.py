"""Approved payload capability from a successful firewall decision."""

from __future__ import annotations

from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Operation
from cognitive_firewall.sdk.client import FirewallUnavailable


_CAPABILITY = object()


class EgressDenied(RuntimeError):
    pass


class ApprovedPayload:
    __slots__ = ("content", "audit_id", "policy_hash")

    def __init__(self, content: str | dict, audit_id: str, policy_hash: str = "", *, _key: object = None):
        if _key is not _CAPABILITY or not audit_id or content is None:
            raise TypeError("approved payloads are issued only after an allow or sanitize decision")
        object.__setattr__(self, "content", content)
        object.__setattr__(self, "audit_id", audit_id)
        object.__setattr__(self, "policy_hash", policy_hash)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("approved payloads are immutable")

    @classmethod
    def _from_decision(cls, content: str | dict, audit_id: str, policy_hash: str) -> "ApprovedPayload":
        return cls(content, audit_id, policy_hash, _key=_CAPABILITY)


class AgentGuard:
    def __init__(self, client):
        self.client = client

    def _at(self, request: EvaluationRequest, operation: Operation) -> ApprovedPayload:
        try:
            result = self.client.evaluate(request.model_copy(update={"operation": operation}))
        except FirewallUnavailable as exc:
            raise EgressDenied("firewall unavailable") from exc
        if result.decision not in {DecisionAction.ALLOW, DecisionAction.SANITIZE} or result.safe_payload is None:
            raise EgressDenied("firewall denied operation")
        return ApprovedPayload._from_decision(result.safe_payload, result.audit_id, result.policy_hash)

    def before_model(self, request: EvaluationRequest) -> ApprovedPayload:
        return self._at(request, Operation.MODEL_INPUT)

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
