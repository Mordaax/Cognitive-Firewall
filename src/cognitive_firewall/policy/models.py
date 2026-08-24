"""Declarative policy models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cognitive_firewall.schemas import DecisionAction, Operation


class MatchCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operations: list[Operation] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    min_severity: int = Field(default=0, ge=0, le=100)
    destination_prefix: str | None = None
    trust_levels: list[str] = Field(default_factory=list)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    priority: int
    when: MatchCriteria = Field(default_factory=MatchCriteria)
    action: DecisionAction
    transformations: dict[str, str] = Field(default_factory=dict)
    ttl_seconds: int | None = Field(default=None, ge=1)


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1)
    rules: list[PolicyRule] = Field(min_length=1)
    policy_hash: str = ""


class PolicyOutcome(BaseModel):
    action: DecisionAction
    transformations: dict[str, str] = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)
    ttl_seconds: int | None = None
