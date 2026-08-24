"""Append missing local firewall credentials without displaying or replacing secrets."""

import argparse
import base64
import re
import secrets
from pathlib import Path


def initialize(path: Path) -> list[str]:
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    present = set(re.findall(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", content))
    generated = {
        "FIREWALL_AGENT_TOKEN": lambda: secrets.token_urlsafe(32),
        "FIREWALL_OPERATOR_TOKEN": lambda: secrets.token_urlsafe(32),
        "FIREWALL_MAPPING_KEY": lambda: base64.b64encode(secrets.token_bytes(32)).decode(),
        "FIREWALL_HMAC_KEY": lambda: base64.b64encode(secrets.token_bytes(32)).decode(),
        "FIREWALL_POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    }
    missing = [name for name in generated if name not in present]
    if missing:
        with path.open("a", encoding="utf-8") as output:
            if content and not content.endswith("\n"):
                output.write("\n")
            for name in missing:
                output.write(f"{name}={generated[name]()}\n")
    return missing


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, nargs="?", default=Path(".env"))
    args = parser.parse_args()
    print("Initialized: " + ", ".join(initialize(args.path)))
