from pathlib import Path

import yaml

from cognitive_firewall.storage.cache import RedisReportCache


def test_compose_publishes_only_loopback_and_has_health_checks():
    compose = yaml.safe_load(Path("compose.yaml").read_text())
    assert "api" in compose["services"] and "dashboard" in compose["services"]
    for service in ("api", "dashboard"):
        for port in compose["services"][service]["ports"]:
            assert str(port).startswith("127.0.0.1:")
    assert compose["services"]["api"]["healthcheck"]
    assert Path("Dockerfile").exists() and Path(".dockerignore").exists()


def test_redis_outage_returns_cache_miss_without_changing_decision_path():
    class UnavailableRedis:
        def get(self, key):
            raise ConnectionError("offline")

        def setex(self, key, ttl, value):
            raise ConnectionError("offline")

    cache = RedisReportCache(UnavailableRedis())
    assert cache.get("summary") is None
    assert cache.set("summary", {"total": 1}) is False
