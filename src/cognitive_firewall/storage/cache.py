"""Optional cache for aggregate reports; admission never reads this cache."""

import json


class RedisReportCache:
    def __init__(self, client, ttl_seconds: int = 30):
        self.client = client
        self.ttl_seconds = ttl_seconds

    def get(self, key: str) -> dict | None:
        try:
            value = self.client.get("firewall:report:" + key)
            return json.loads(value) if value else None
        except Exception:
            return None

    def set(self, key: str, summary: dict) -> bool:
        try:
            self.client.setex(
                "firewall:report:" + key,
                self.ttl_seconds,
                json.dumps(summary, separators=(",", ":")),
            )
            return True
        except Exception:
            return False
