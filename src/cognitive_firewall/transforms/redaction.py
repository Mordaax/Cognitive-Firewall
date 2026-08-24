"""Apply policy transformations without mutating caller-owned payloads."""

from __future__ import annotations

from typing import Any

from cognitive_firewall.policy.models import PolicyOutcome
from cognitive_firewall.schemas import Finding
from cognitive_firewall.transforms.pseudonymization import MappingStore, normalize_identifier


class TransformationError(RuntimeError):
    pass


def _replacement(
    category: str,
    action: str,
    value: str,
    case_id: str,
    store: MappingStore,
    ttl_seconds: int | None,
) -> str:
    if action == "redact":
        return f"[REDACTED:{category.upper()}]"
    if action == "strip" and category == "injection":
        return "[REMOVED:UNTRUSTED_INSTRUCTION]"
    if action == "pseudonymize":
        return store.get_or_create(
            case_id, category, normalize_identifier(category, value), ttl_seconds=ttl_seconds
        )
    raise TransformationError("unsupported transformation")


def _transform_text(
    text: str,
    findings: list[Finding],
    outcome: PolicyOutcome,
    case_id: str,
    mapping_store: MappingStore,
) -> str:
    if not findings:
        return text
    spans: list[tuple[int, int, Finding]] = []
    for finding in findings:
        if finding.category == "secret":
            raise TransformationError("secret content cannot be transformed")
        if (
            finding.start is None
            or finding.end is None
            or finding.start < 0
            or finding.end > len(text)
            or finding.start >= finding.end
        ):
            raise TransformationError("finding has no safe span")
        if finding.category not in outcome.transformations:
            raise TransformationError("finding has no required transformation")
        spans.append((finding.start, finding.end, finding))
    spans.sort(key=lambda item: (item[0], item[1]))
    groups: list[tuple[int, int, list[Finding]]] = []
    for start, end, finding in spans:
        if groups and start < groups[-1][1]:
            prev_start, prev_end, prev_findings = groups[-1]
            groups[-1] = (prev_start, max(prev_end, end), prev_findings + [finding])
        else:
            groups.append((start, end, [finding]))
    output = text
    for start, end, cluster in reversed(groups):
        if len({finding.category for finding in cluster}) > 1:
            category, action = "pii", "redact"
        else:
            category = cluster[0].category
            action = outcome.transformations[category]
        output = (
            output[:start]
            + _replacement(
                category, action, text[start:end], case_id, mapping_store, outcome.ttl_seconds
            )
            + output[end:]
        )
    return output


def transform_payload(
    payload: str | dict[str, Any],
    findings: list[Finding],
    outcome: PolicyOutcome,
    case_id: str,
    mapping_store: MappingStore,
) -> str | dict[str, Any]:
    grouped: dict[str | None, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.json_path, []).append(finding)

    def visit(value: Any, path: str | None) -> Any:
        if isinstance(value, str):
            return _transform_text(value, grouped.get(path, []), outcome, case_id, mapping_store)
        if isinstance(value, dict):
            return {
                key: visit(child, f"{path}.{key}" if path else f"$.{key}")
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [
                visit(child, f"{path}[{i}]" if path else f"$[{i}]") for i, child in enumerate(value)
            ]
        return value

    return visit(payload, "$" if isinstance(payload, dict) else None)
