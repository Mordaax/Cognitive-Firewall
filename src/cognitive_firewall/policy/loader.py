"""Safe YAML loading and policy version hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import ValidationError
import yaml

from cognitive_firewall.policy.models import PolicyBundle


def load_policy(path: Path) -> PolicyBundle:
    try:
        raw = path.read_bytes()
        parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("policy must be an object")
        bundle = PolicyBundle.model_validate(parsed)
        if len({rule.id for rule in bundle.rules}) != len(bundle.rules):
            raise ValueError("policy rule IDs must be unique")
        bundle.policy_hash = hashlib.sha256(raw).hexdigest()
        return bundle
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ValueError("invalid policy file") from exc
