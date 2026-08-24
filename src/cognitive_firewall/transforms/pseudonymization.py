"""Contract for case-scoped pseudonym mapping stores."""

from __future__ import annotations

from typing import Protocol


class MappingStore(Protocol):
    def get_or_create(self, case_id: str, category: str, normalized_value: str) -> str: ...


def normalize_identifier(category: str, value: str) -> str:
    cleaned = value.strip()
    return cleaned.casefold() if category in {"email", "username", "customer_id"} else cleaned
