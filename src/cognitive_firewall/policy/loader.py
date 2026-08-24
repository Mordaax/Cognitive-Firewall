"""Safe YAML loading and policy version hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from cognitive_firewall.policy.models import PolicyBundle


def load_policy(path: Path) -> PolicyBundle:
    try:
        return load_policy_bytes(path.read_bytes())
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ValueError("invalid policy file") from exc


def load_policy_bytes(raw: bytes) -> PolicyBundle:
    try:
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("policy must be an object")
        bundle = PolicyBundle.model_validate(parsed)
        if len({rule.id for rule in bundle.rules}) != len(bundle.rules):
            raise ValueError("policy rule IDs must be unique")
        bundle.policy_hash = hashlib.sha256(raw).hexdigest()
        return bundle
    except (yaml.YAMLError, ValidationError) as exc:
        raise ValueError("invalid policy file") from exc
