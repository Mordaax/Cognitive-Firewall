"""Explainable, bounded finding scores."""

from __future__ import annotations

from cognitive_firewall.schemas import Finding


def score_findings(findings: list[Finding]) -> tuple[int, int]:
    injection = max((f.severity for f in findings if f.category == "injection"), default=0)
    privacy = max((f.severity for f in findings if f.category != "injection"), default=0)
    return min(100, injection), min(100, privacy)
