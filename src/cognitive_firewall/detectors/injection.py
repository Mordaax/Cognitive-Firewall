"""Deterministic instruction-in-data findings."""

from __future__ import annotations

import base64
import re
from typing import Any

from cognitive_firewall.detectors.common import walk_strings
from cognitive_firewall.schemas import Finding


_RULES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("instruction_override", re.compile(r"\b(?:ignore|disregard|forget)\b.{0,50}\b(?:previous|prior|all|system)\b.{0,35}\b(?:instructions?|rules?|prompts?)\b", re.I | re.S), 90),
    ("authority_spoofing", re.compile(r"(?:^|\n)\s*(?:system|developer)\s*:\s*\S+", re.I), 90),
    ("exfiltration_instruction", re.compile(r"\b(?:send|upload|post|transmit)\b.{0,100}\bhttps?://\S+", re.I | re.S), 95),
)
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


def detect_injection(payload: str | dict[str, Any], *, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in walk_strings(payload):
        for reason, pattern, severity in _RULES:
            for match in pattern.finditer(text):
                local_severity = severity
                if "attack example" in text.lower() or "quotes" in text.lower():
                    local_severity = min(local_severity, 35)
                findings.append(Finding(category="injection", severity=local_severity, reason_code=reason,
                                        start=match.start(), end=match.end(), json_path=path, detector="rules"))
        for match in _B64.finditer(text):
            try:
                decoded = base64.b64decode(match.group(0), validate=True).decode("utf-8", errors="ignore")
            except (ValueError, UnicodeError):
                continue
            if any(rule.search(decoded) for _, rule, _ in _RULES):
                findings.append(Finding(category="injection", severity=85, reason_code="encoded_instruction",
                                        start=match.start(), end=match.end(), json_path=path, detector="base64"))
    return findings
