"""Public request, finding, and decision contracts."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

MAX_PAYLOAD_BYTES = 65_536
_OPAQUE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def _validate_opaque_id(value: str, *, allow_empty: bool = False) -> str:
    if allow_empty and not value:
        return value
    from cognitive_firewall.detectors.pii import detect_pii
    from cognitive_firewall.detectors.secrets import detect_secrets

    if not _OPAQUE_ID.fullmatch(value) or detect_pii(value) or detect_secrets(value):
        raise ValueError("identifier must be opaque and contain no sensitive data")
    return value


class Operation(StrEnum):
    MODEL_INPUT = "model_input"
    RETRIEVAL = "retrieval"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    MODEL_OUTPUT = "model_output"
    EXPORT = "export"


class DecisionAction(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class Provenance(BaseModel):
    source_id: str = ""
    trust_level: str = "untrusted"
    fetched_at: str | None = None

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return _validate_opaque_id(value, allow_empty=True)


class Finding(BaseModel):
    category: str
    severity: int = Field(ge=0, le=100)
    reason_code: str
    start: int | None = None
    end: int | None = None
    json_path: str | None = None
    detector: str = ""


class EvaluationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    operation: Operation
    payload: str | dict[str, Any]
    source: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    provenance: Provenance | None = None
    approval_id: str | None = None
    provenance_id: str | None = Field(default=None, max_length=96)
    lineage_ids: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("case_id", "agent_id")
    @classmethod
    def validate_opaque_id(cls, value: str) -> str:
        return _validate_opaque_id(value)

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, value: str | dict[str, Any]) -> str | dict[str, Any]:
        if not isinstance(value, (str, dict)):
            raise ValueError("payload must be text or an object")
        encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload exceeds 65536 bytes")
        return value


class EvaluationResponse(BaseModel):
    decision: DecisionAction
    safe_payload: str | dict[str, Any] | None
    findings: list[Finding]
    reason_codes: list[str]
    injection_score: int = Field(ge=0, le=100)
    privacy_score: int = Field(ge=0, le=100)
    policy_hash: str
    audit_id: str
    memory_id: str | None = None
    approval_id: str | None = None
    provenance_id: str | None = None
