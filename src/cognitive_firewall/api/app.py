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
from cognitive_firewall.storage.approvals import ApprovalStore
from cognitive_firewall.storage.audit import SqlAuditStore
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
    policy = load_policy(Path(settings.policy_path))
    policies = SqlPolicyStore(db)
    if policies.active_hash() != policy.policy_hash:
        policies.activate(policy)
    audit = SqlAuditStore(db)
    approvals = ApprovalStore(db, audit)
    evaluator = Evaluator(policy, audit, SqlMappingStore(db, encryption_key=_key(settings.mapping_key),
                                                     hmac_key=_key(settings.hmac_key)),
                          SqlMemoryStore(db), approvals)
    install_routes(app, db=db, evaluator=evaluator, approvals=approvals,
                   policies=policies, auth=Authenticator(settings))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "invalid request"})

    return app
