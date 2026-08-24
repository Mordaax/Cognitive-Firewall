"""Deterministic policy matching with explicit precedence."""

from __future__ import annotations

from cognitive_firewall.policy.models import PolicyBundle, PolicyOutcome, PolicyRule
from cognitive_firewall.schemas import DecisionAction, EvaluationRequest, Finding


def _matches(rule: PolicyRule, request: EvaluationRequest, findings: list[Finding]) -> bool:
    criteria = rule.when
    if criteria.operations and request.operation not in criteria.operations:
        return False
    if criteria.destination_prefix and not request.destination.startswith(criteria.destination_prefix):
        return False
    trust = request.provenance.trust_level if request.provenance else "untrusted"
    if criteria.trust_levels and trust not in criteria.trust_levels:
        return False
    if criteria.categories:
        return any(f.category in criteria.categories and f.severity >= criteria.min_severity for f in findings)
    if criteria.min_severity:
        return any(f.severity >= criteria.min_severity for f in findings)
    return True


def evaluate_policy(request: EvaluationRequest, findings: list[Finding], policy: PolicyBundle) -> PolicyOutcome:
    for rule in sorted(policy.rules, key=lambda item: item.priority, reverse=True):
        if _matches(rule, request, findings):
            return PolicyOutcome(action=rule.action, transformations=rule.transformations,
                                 reason_codes=[rule.id], ttl_seconds=rule.ttl_seconds)
    return PolicyOutcome(action=DecisionAction.BLOCK, reason_codes=["policy_no_match"])
