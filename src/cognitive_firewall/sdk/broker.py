"""Trusted host dispatch boundary; model output never selects executable code."""
from __future__ import annotations

import json
from types import MappingProxyType
from typing import Any, Callable

from cognitive_firewall.schemas import EvaluationRequest


def _snapshot(value: Any) -> dict:
    if not isinstance(value, dict):
        raise PermissionError('tool arguments must be an object')
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise PermissionError('invalid tool arguments') from exc


class ToolBroker:
    def __init__(self, evaluator: Any, handlers: dict[str, Callable], agent_id: str, *, case_id: str):
        if not callable(getattr(evaluator, 'evaluate', None)) or not agent_id or not case_id:
            raise ValueError('trusted evaluator and bound agent identity required')
        if not isinstance(handlers, dict) or any(
            not isinstance(key, str) or not key or not callable(value)
            for key, value in handlers.items()
        ):
            raise ValueError('invalid host handler registry')
        self._evaluator = evaluator
        self._handlers = MappingProxyType(dict(handlers))
        self._agent_id = agent_id
        self._case_id = case_id

    def execute(self, request: EvaluationRequest) -> Any:
        # Own the request before evaluation so callers cannot swap arguments/targets.
        req = EvaluationRequest.model_validate(request.model_dump(mode='json'))
        if (req.agent_id != self._agent_id or req.case_id != self._case_id
                or req.operation != 'tool_request'):
            raise PermissionError('broker identity or operation denied')
        handler = self._handlers.get(req.destination)
        if handler is None:
            raise PermissionError('unregistered host handler')
        original = _snapshot(req.payload)
        response = self._evaluator.evaluate(req.model_copy(deep=True))
        if response.decision not in {'allow', 'sanitize'}:
            raise PermissionError('firewall denied execution')
        approved = _snapshot(response.safe_payload)
        # Equality via canonical JSON distinguishes booleans from numbers as well.
        if json.dumps(approved, sort_keys=True) != json.dumps(original, sort_keys=True):
            raise PermissionError('changed action requires a new evaluation and approval')
        return handler(approved)

