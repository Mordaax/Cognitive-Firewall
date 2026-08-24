"""Synchronous and asynchronous authenticated API clients."""

from __future__ import annotations

import httpx

from cognitive_firewall.schemas import EvaluationRequest, EvaluationResponse


class FirewallUnavailable(RuntimeError):
    pass


class FirewallClient:
    def __init__(self, base_url: str, token: str, *, transport: httpx.BaseTransport | None = None,
                 timeout: float = 10.0):
        self._client = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {token}"},
                                    transport=transport, timeout=timeout)

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        try:
            result = self._client.post("/v1/evaluations", json=request.model_dump(mode="json"))
            result.raise_for_status()
            return EvaluationResponse.model_validate(result.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise FirewallUnavailable("firewall evaluation unavailable") from exc

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "FirewallClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncFirewallClient:
    def __init__(self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 10.0):
        self._client = httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {token}"},
                                         transport=transport, timeout=timeout)

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        try:
            result = await self._client.post("/v1/evaluations", json=request.model_dump(mode="json"))
            result.raise_for_status()
            return EvaluationResponse.model_validate(result.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise FirewallUnavailable("firewall evaluation unavailable") from exc

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncFirewallClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
