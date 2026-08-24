"""Local credential and token detection."""

from __future__ import annotations

import re
from typing import Any

from cognitive_firewall.detectors.common import walk_strings
from cognitive_firewall.schemas import Finding


_TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})\b")
_SECRET_KEYS = {"api_key", "apikey", "access_token", "secret", "password", "private_key"}


def detect_secrets(payload: str | dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in walk_strings(payload):
        matches = list(_TOKEN.finditer(text))
        for match in matches:
            findings.append(Finding(category="secret", severity=100, reason_code="secret_detected",
                                    start=match.start(), end=match.end(), json_path=path, detector="secret_rules"))
        key_name = path.rsplit(".", 1)[-1].lower() if path else ""
        if key_name in _SECRET_KEYS and text and not matches:
            findings.append(Finding(category="secret", severity=100, reason_code="secret_field",
                                    start=0, end=len(text), json_path=path, detector="schema"))
    return findings
