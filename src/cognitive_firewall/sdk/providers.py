"""Provider boundaries accept only approved payload capabilities."""

from __future__ import annotations

import os
from typing import Any, Callable

from cognitive_firewall.schemas import Operation
from cognitive_firewall.sdk.guard import ApprovedPayload, EgressDenied


def _content(payload: ApprovedPayload, destination: str) -> str:
    if not isinstance(payload, ApprovedPayload):
        raise TypeError("provider requires ApprovedPayload")
    if payload.operation != Operation.MODEL_INPUT or payload.destination != destination:
        raise EgressDenied("provider requires matching model input approval")
    return payload._wire_content


class OpenAIAdapter:
    def __init__(
        self,
        *,
        transport: Callable[[str], Any] | None = None,
        client: Any = None,
        model: str = "gpt-4.1-mini",
    ):
        self.transport = transport
        self.client = client
        self.model = model

    def send(self, payload: ApprovedPayload) -> Any:
        content = _content(payload, "openai")
        if self.transport is not None:
            return self.transport(content)
        if self.client is None:
            from openai import OpenAI

            self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_API_KEY"))
        return self.client.responses.create(model=self.model, input=content)


class ClaudeAdapter:
    def __init__(
        self,
        *,
        transport: Callable[[str], Any] | None = None,
        client: Any = None,
        model: str = "claude-sonnet-4-5",
    ):
        self.transport = transport
        self.client = client
        self.model = model

    def send(self, payload: ApprovedPayload) -> Any:
        content = _content(payload, "claude")
        if self.transport is not None:
            return self.transport(content)
        if self.client is None:
            from anthropic import Anthropic

            self.client = Anthropic(
                api_key=os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
            )
        return self.client.messages.create(
            model=self.model, max_tokens=1024, messages=[{"role": "user", "content": content}]
        )
