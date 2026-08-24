"""Deterministic instruction-in-data findings with bounded inspection copies."""
from __future__ import annotations

import base64
import html
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

from cognitive_firewall.detectors.common import walk_strings
from cognitive_firewall.schemas import Finding

_RULES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ('instruction_override', re.compile(
        r'\b(?:ignore|disregard|forget)\b.{0,50}\b(?:previous|prior|all|system)\b.{0,35}\b(?:instructions?|rules?|prompts?)\b',
        re.I | re.S), 90),
    ('authority_spoofing', re.compile(r'(?:^|\n)\s*(?:system|developer)\s*:\s*\S+', re.I), 90),
    ('exfiltration_instruction', re.compile(
        r'\b(?:send|upload|post|transmit)\b.{0,100}\bhttps?://\S+', re.I | re.S), 95),
)
_B64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])')
_INSPECTION_LIMIT = 65_536


def _normalize(text: str) -> str:
    text = unicodedata.normalize('NFKC', html.unescape(unquote(text)))
    return ''.join(c for c in text if unicodedata.category(c) != 'Cf')


def detect_injection(payload: str | dict[str, Any], *, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in walk_strings(payload):
        if len(text.encode('utf-8')) > _INSPECTION_LIMIT:
            findings.append(Finding(category='injection', severity=100,
                reason_code='inspection_limit_exceeded', json_path=path, detector='normalization'))
            continue
        copies = [text]
        for _ in range(2):
            normalized = _normalize(copies[-1])
            if normalized in copies:
                break
            copies.append(normalized)
        for index, copy in enumerate(copies):
            for reason, pattern, severity in _RULES:
                for match in pattern.finditer(copy):
                    findings.append(Finding(category='injection', severity=severity,
                        reason_code=reason, start=match.start() if index == 0 else None,
                        end=match.end() if index == 0 else None, json_path=path,
                        detector='rules' if index == 0 else 'normalization'))
            for match in _B64.finditer(copy):
                try:
                    decoded = base64.b64decode(match.group(0), validate=True).decode('utf-8')
                except (ValueError, UnicodeError):
                    continue
                if any(rule.search(_normalize(decoded)) for _, rule, _ in _RULES):
                    findings.append(Finding(category='injection', severity=90,
                        reason_code='encoded_instruction', start=match.start() if index == 0 else None,
                        end=match.end() if index == 0 else None, json_path=path, detector='base64'))
    return findings
