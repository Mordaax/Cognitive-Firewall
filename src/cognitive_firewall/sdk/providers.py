"""Provider boundaries accept only approved payload capabilities."""

from __future__ import annotations

import json
from typing import Callable, Any

from cognitive_firewall.sdk.guard import ApprovedPayload


def _content(payload: ApprovedPayload) -> str:
    if not isinstance(payload, ApprovedPayload):
        raise TypeError("provider requires ApprovedPayload")
    return payload.content if isinstance(payload.content, str) else json.dumps(payload.content, ensure_ascii=False)


class OpenAIAdapter:
    def __init__(self, *, transport: Callable[[str], Any] | None = None, client: Any = None,
                 model: str = "gpt-4.1-mini"):
        self.transport = transport
        self.client = client
        self.model = model

    def send(self, payload: ApprovedPayload) -> Any:
        content = _content(payload)
        if self.transport is not None:
            return self.transport(content)
        if self.client is None:
            from openai import OpenAI
            self.client = OpenAI()
        return self.client.responses.create(model=self.model, input=content)


class ClaudeAdapter:
    def __init__(self, *, transport: Callable[[str], Any] | None = None, client: Any = None,
                 model: str = "claude-sonnet-4-5"):
        self.transport = transport
        self.client = client
        self.model = model

    def send(self, payload: ApprovedPayload) -> Any:
        content = _content(payload)
        if self.transport is not None:
            return self.transport(content)
        if self.client is None:
            from anthropic import Anthropic
            self.client = Anthropic()
        return self.client.messages.create(model=self.model, max_tokens=1024,
                                           messages=[{"role": "user", "content": content}])
