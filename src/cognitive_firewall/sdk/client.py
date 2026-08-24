"""Synchronous and asynchronous authenticated API clients."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from cognitive_firewall.schemas import EvaluationRequest, EvaluationResponse


class FirewallUnavailable(RuntimeError):
    pass


def _local_only(base_url: str, transport: object | None) -> None:
    if transport is not None:
        return
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("firewall API must be on loopback to keep raw content local")


class FirewallClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ):
        _local_only(base_url, transport)
        self._client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
            timeout=timeout,
        )

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
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
    ):
        _local_only(base_url, transport)
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
            timeout=timeout,
        )

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        try:
            result = await self._client.post(
                "/v1/evaluations", json=request.model_dump(mode="json")
            )
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
