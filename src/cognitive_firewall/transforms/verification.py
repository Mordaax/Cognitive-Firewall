"""Post-transformation checks before context admission."""

from __future__ import annotations

from typing import Any

from cognitive_firewall.detectors.injection import detect_injection
from cognitive_firewall.detectors.pii import detect_pii
from cognitive_firewall.detectors.secrets import detect_secrets
from cognitive_firewall.policy.models import PolicyOutcome
from cognitive_firewall.schemas import Finding
from cognitive_firewall.transforms.redaction import TransformationError


def verify_transformation(
    original_findings: list[Finding], transformed: str | dict[str, Any], outcome: PolicyOutcome
) -> None:
    required = {
        finding.category
        for finding in original_findings
        if finding.category in outcome.transformations
    }
    remaining = (
        detect_pii(transformed)
        + detect_secrets(transformed)
        + detect_injection(transformed, source="transformed")
    )
    if any(f.category in required or f.category == "secret" for f in remaining):
        raise TransformationError("transformation verification failed")
