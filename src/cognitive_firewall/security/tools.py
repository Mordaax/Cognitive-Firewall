"""Host-owned, deny-by-default tool capabilities; no tool execution here."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field

from cognitive_firewall.schemas import EvaluationRequest, Operation


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agents: list[str] = Field(min_length=1)
    input_schema: dict
    require_approval: bool = False
    read_only: bool = False
    path_fields: dict[str, list[str]] = Field(default_factory=dict)
    recipient_fields: dict[str, list[str]] = Field(default_factory=dict)
    host_fields: dict[str, list[str]] = Field(default_factory=dict)


class RegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: dict[str, ToolSpec] = Field(default_factory=dict)


def _reject_refs(value):
    if isinstance(value, dict):
        if "$ref" in value or "$dynamicRef" in value:
            raise ValueError("schema references are not allowed")
        for child in value.values():
            _reject_refs(child)
    elif isinstance(value, list):
        for child in value:
            _reject_refs(child)


def _field(arguments: dict, field: str) -> str:
    value = arguments
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            raise PermissionError("resource field missing")
        value = value[part]
    if not isinstance(value, str) or not value:
        raise PermissionError("invalid resource field")
    return value


class ToolRegistry:
    def __init__(self, config: RegistryConfig):
        # Snapshot host policy: mutations of input dictionaries cannot change it.
        self._config = RegistryConfig.model_validate(config.model_dump())
        for name, spec in self._config.tools.items():
            if not name.startswith(("tool:", "privileged:")):
                raise ValueError("tool name requires tool: or privileged: prefix")
            _reject_refs(spec.input_schema)
            Draft202012Validator.check_schema(spec.input_schema)
            if (spec.input_schema.get("type") != "object"
                    or spec.input_schema.get("additionalProperties") is not False):
                raise ValueError("tool schemas must be closed JSON objects")
            for roots in spec.path_fields.values():
                if not roots or any(not Path(root).is_absolute() for root in roots):
                    raise ValueError("path roots must be absolute")
        raw = json.dumps(self._config.model_dump(), sort_keys=True, separators=(",", ":"))
        self.policy_hash = hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def from_dict(cls, value: dict) -> ToolRegistry:
        return cls(RegistryConfig.model_validate(value))

    @classmethod
    def from_file(cls, path: Path) -> ToolRegistry:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))

    def check(self, request: EvaluationRequest) -> bool:
        if request.operation != Operation.TOOL_REQUEST:
            raise PermissionError("tool request required")
        spec = self._config.tools.get(request.destination)
        if spec is None or request.agent_id not in spec.agents:
            raise PermissionError("tool not granted")
        if not isinstance(request.payload, dict):
            raise PermissionError("structured tool arguments required")
        if not Draft202012Validator(spec.input_schema).is_valid(request.payload):
            raise PermissionError("invalid tool arguments")
        for field, roots in spec.path_fields.items():
            raw = _field(request.payload, field)
            # Reject Windows device paths, alternate streams and UNC targets.
            if (not Path(raw).is_absolute() or raw.startswith(("\\\\", "//"))
                    or ":" in raw[2:]):
                raise PermissionError("unsupported file target")
            candidate = Path(raw).resolve()
            if not any(candidate.is_relative_to(Path(root).resolve()) for root in roots):
                raise PermissionError("file target not granted")
        for field, recipients in spec.recipient_fields.items():
            if _field(request.payload, field) not in recipients:
                raise PermissionError("recipient not granted")
        for field, hosts in spec.host_fields.items():
            try:
                url = urlsplit(_field(request.payload, field))
                hostname = (url.hostname or "").encode("idna").decode().lower()
                allowed = {host.encode("idna").decode().lower() for host in hosts}
                if (url.scheme != "https" or url.username is not None
                        or url.password is not None or url.port not in (None, 443)
                        or hostname not in allowed or url.fragment):
                    raise PermissionError("URL target not granted")
                try:
                    address = ipaddress.ip_address(hostname)
                except ValueError:
                    address = None
                if address is not None and not address.is_global:
                    raise PermissionError("private network targets are forbidden")
            except (ValueError, UnicodeError) as exc:
                raise PermissionError("invalid URL target") from exc
        return spec.require_approval or not spec.read_only
