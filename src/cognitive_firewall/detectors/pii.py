"""Local schema-aware and free-text PII detection."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cognitive_firewall.detectors.common import walk_strings
from cognitive_firewall.schemas import Finding


_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)")
_IP = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_CUSTOMER = re.compile(r"\b(?:CUS|CUST|CUSTOMER)[-_]?[A-Z0-9]{4,}\b", re.I)
_USERNAME = re.compile(r"\b(?:user(?:name)?|handle)\s*[:=]\s*([A-Za-z][\w.-]{2,})", re.I)


def detect_pii(payload: str | dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str | None, int, int]] = set()
    for path, text in walk_strings(payload):
        checks = (("email", _EMAIL), ("phone", _PHONE), ("ip", _IP), ("customer_id", _CUSTOMER), ("username", _USERNAME))
        for category, pattern in checks:
            for match in pattern.finditer(text):
                start, end = match.span(1) if category == "username" else match.span()
                if category == "ip":
                    try:
                        ipaddress.ip_address(text[start:end])
                    except ValueError:
                        continue
                key = (category, path, start, end)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(category=category, severity=75 if category in {"phone", "ip"} else 65,
                                            reason_code=f"pii_{category}", start=start, end=end, json_path=path, detector="pii"))
        key_name = path.rsplit(".", 1)[-1].lower() if path else ""
        hinted = "username" if key_name in {"username", "user_name", "handle"} else (
            "customer_id" if key_name in {"customer_id", "customerid", "account_id"} else None
        )
        if hinted and text and (hinted, path, 0, len(text)) not in seen:
            findings.append(Finding(category=hinted, severity=65, reason_code=f"pii_{hinted}",
                                    start=0, end=len(text), json_path=path, detector="schema"))
    return findings
