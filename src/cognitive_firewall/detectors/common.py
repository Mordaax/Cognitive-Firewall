"""Walk text fields while retaining stable JSON paths."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def walk_strings(payload: str | dict[str, Any]) -> Iterator[tuple[str | None, str]]:
    if isinstance(payload, str):
        yield None, payload
        return

    def visit(value: Any, path: str) -> Iterator[tuple[str, str]]:
        if isinstance(value, str):
            yield path, value
        elif isinstance(value, dict):
            for key, child in value.items():
                yield from visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from visit(child, f"{path}[{index}]")

    yield from visit(payload, "$")
