"""Constant-time bearer authentication with distinct agent and operator roles."""

import hmac
from dataclasses import dataclass
from typing import Literal

from cognitive_firewall.config import Settings


@dataclass(frozen=True)
class Principal:
    role: Literal["agent", "operator"]


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

    def require_role(self, authorization: str, role: Literal["agent", "operator"]) -> Principal:
        scheme, separator, token = authorization.partition(" ")
        candidate = token if separator and scheme.lower() == "bearer" else ""
        agent = hmac.compare_digest(candidate, self._agent)
        operator = hmac.compare_digest(candidate, self._operator)
        if role == "operator" and operator:
            return Principal("operator")
        if role == "agent" and (agent or operator):
            return Principal("operator" if operator else "agent")
        raise PermissionError("invalid credentials or role")
