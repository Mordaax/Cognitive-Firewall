"""Validated environment configuration without reading secret values into logs."""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    agent_token: str
    operator_token: str
    mapping_key: str
    hmac_key: str
    database_url: str = "sqlite:///./firewall.sqlite3"
    policy_path: str = "policies/default.yaml"

    @classmethod
    def from_env(cls) -> "Settings":
        names = (
            "FIREWALL_AGENT_TOKEN",
            "FIREWALL_OPERATOR_TOKEN",
            "FIREWALL_MAPPING_KEY",
            "FIREWALL_HMAC_KEY",
        )
        values = {name: os.environ.get(name, "") for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError("Missing required configuration: " + ", ".join(missing))
        if values[names[0]] == values[names[1]]:
            raise RuntimeError("Agent and operator credentials must differ")
        return cls(
            agent_token=values[names[0]],
            operator_token=values[names[1]],
            mapping_key=values[names[2]],
            hmac_key=values[names[3]],
            database_url=os.environ.get("FIREWALL_DATABASE_URL", "sqlite:///./firewall.sqlite3"),
            policy_path=os.environ.get("FIREWALL_POLICY_PATH", "policies/default.yaml"),
        )
