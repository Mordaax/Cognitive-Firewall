"""Public request, finding, and decision contracts."""

from __future__ import annotations

from enum import StrEnum
import json
from typing import Any

from pydantic import BaseModel, Field, field_validator


MAX_PAYLOAD_BYTES = 65_536


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


class Finding(BaseModel):
    category: str
    severity: int = Field(ge=0, le=100)
    reason_code: str
    start: int | None = None
    end: int | None = None
    json_path: str | None = None
    detector: str = ""


class EvaluationRequest(BaseModel):
    operation: Operation
    payload: str | dict[str, Any]
    source: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    provenance: Provenance | None = None
    approval_id: str | None = None

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

