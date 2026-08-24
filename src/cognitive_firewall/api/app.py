"""Application factory; secrets are injected and never included in errors."""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from cognitive_firewall.api.auth import Authenticator
from cognitive_firewall.api.routes import install_routes
from cognitive_firewall.config import Settings
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.security.provenance import ProvenanceStore
from cognitive_firewall.security.tools import ToolRegistry
from cognitive_firewall.storage.approvals import ApprovalStore
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.cache import RedisReportCache
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore
from cognitive_firewall.storage.memory import SqlMemoryStore
from cognitive_firewall.storage.policies import SqlPolicyStore


def _key(value: str) -> bytes:
    if len(value.encode()) == 32:
        return value.encode()
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32:
        raise ValueError("invalid key length")
    return decoded


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Cognitive Firewall", version="0.1.0")
    db = Database(settings.database_url)
    db.create_all()
    policies = SqlPolicyStore(db)
    policy = policies.active_bundle()
    if policy is None:
        policy_path = Path(settings.policy_path)
        policy = load_policy(policy_path)
        policies.activate(policy, policy_path.read_bytes())
    audit = SqlAuditStore(db)
    approvals = ApprovalStore(db, audit)
    semantic_detector = None
    if settings.semantic_model_path:
        from cognitive_firewall.detectors.semantic import LocalSemanticDetector
        semantic_detector = LocalSemanticDetector(
            settings.semantic_model_path, malicious_labels=set(settings.semantic_labels))
    evaluator = Evaluator(
        policy,
        audit,
        SqlMappingStore(
            db, encryption_key=_key(settings.mapping_key), hmac_key=_key(settings.hmac_key)
        ),
        SqlMemoryStore(db),
        approvals,
        policy_store=policies,
        tool_registry=ToolRegistry.from_file(Path(settings.tools_path)),
        provenance_store=ProvenanceStore(db),
        semantic_detector=semantic_detector,
        semantic_threshold=settings.semantic_threshold,
    )
    app.state.evaluator = evaluator
    cache = None
    if settings.redis_url:
        import redis

        cache = RedisReportCache(redis.Redis.from_url(settings.redis_url))
    install_routes(
        app,
        db=db,
        evaluator=evaluator,
        approvals=approvals,
        policies=policies,
        auth=Authenticator(settings),
        report_cache=cache,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "invalid request"})

    return app
