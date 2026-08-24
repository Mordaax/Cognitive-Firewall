"""Constant-time bearer authentication with distinct agent and operator roles."""

import hmac
from dataclasses import dataclass
from typing import Literal

from cognitive_firewall.config import Settings
from cognitive_firewall.schemas import _validate_opaque_id


@dataclass(frozen=True)
class Principal:
    role: Literal["agent", "operator"]
    agent_id: str | None = None


class Authenticator:
    def __init__(self, settings: Settings):
        if (
            not settings.agent_token
            or not settings.operator_token
            or settings.agent_token == settings.operator_token
        ):
            raise ValueError("distinct credentials are required")
        self._agent = settings.agent_token
        self._operator = settings.operator_token
        self._tokens = {settings.agent_id: settings.agent_token, **settings.agent_tokens}
        if (settings.agent_id in settings.agent_tokens
                or len(set(self._tokens.values())) != len(self._tokens)
                or settings.operator_token in self._tokens.values()):
            raise ValueError("agent credentials must be unique and separate from operator")
        for identity, token in self._tokens.items():
            _validate_opaque_id(identity)
            if not isinstance(token, str) or not token:
                raise ValueError("nonempty agent token required")

    def require_role(self, authorization: str, role: Literal["agent", "operator"]) -> Principal:
        scheme, separator, token = authorization.partition(" ")
        candidate = token if separator and scheme.lower() == "bearer" else ""
        identity = None
        for agent_id, credential in self._tokens.items():
            if hmac.compare_digest(candidate, credential):
                identity = agent_id
        operator = hmac.compare_digest(candidate, self._operator)
        if role == "operator" and operator:
            return Principal("operator")
        if role == "agent" and operator:
            return Principal("operator")
        if role == "agent" and identity is not None:
            return Principal("agent", identity)
        raise PermissionError("invalid credentials or role")
