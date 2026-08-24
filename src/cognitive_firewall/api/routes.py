"""Authenticated evaluation and operator management routes."""

from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from cognitive_firewall.api.auth import Authenticator, Principal
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy_bytes
from cognitive_firewall.schemas import EvaluationRequest, EvaluationResponse
from cognitive_firewall.storage.approvals import ApprovalStore
from cognitive_firewall.storage.db import AuditRow, Database
from cognitive_firewall.storage.policies import SqlPolicyStore


class BatchResponse(BaseModel):
    items: list[EvaluationResponse]


class PolicyActivation(BaseModel):
    yaml: str = Field(max_length=65536)


class ApprovalDecision(BaseModel):
    approve: bool


def install_routes(app: FastAPI, *, db: Database, evaluator: Evaluator,
                   approvals: ApprovalStore, policies: SqlPolicyStore, auth: Authenticator) -> None:
    def agent(authorization: Annotated[str | None, Header()] = None) -> Principal:
        try:
            return auth.require_role(authorization or "", "agent")
        except PermissionError:
            raise HTTPException(status_code=401 if not authorization else 403, detail="unauthorized") from None

    def operator(authorization: Annotated[str | None, Header()] = None) -> Principal:
        try:
            return auth.require_role(authorization or "", "operator")
        except PermissionError:
            raise HTTPException(status_code=401 if not authorization else 403, detail="unauthorized") from None

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        try:
            with db.session() as session:
                session.execute(text("SELECT 1"))
            if evaluator.policy is None or policies.active_hash() != evaluator.policy.policy_hash:
                raise RuntimeError("policy unavailable")
        except Exception:
            raise HTTPException(status_code=503, detail="not ready") from None
        return {"status": "ready"}

    @app.post("/v1/evaluations", response_model=EvaluationResponse)
    def evaluate(request: EvaluationRequest, _: Annotated[Principal, Depends(agent)]) -> EvaluationResponse:
        return evaluator.evaluate(request)

    @app.post("/v1/evaluations/batch", response_model=BatchResponse)
    def evaluate_batch(requests: list[EvaluationRequest], _: Annotated[Principal, Depends(agent)]) -> BatchResponse:
        if len(requests) > 100:
            raise HTTPException(status_code=422, detail="batch too large")
        return BatchResponse(items=[evaluator.evaluate(request) for request in requests])

    @app.get("/v1/policies")
    def get_policies(_: Annotated[Principal, Depends(operator)]) -> dict:
        policy = evaluator.policy
        return {"active_policy_hash": policies.active_hash(), "version": policy.version if policy else None,
                "rule_ids": [rule.id for rule in policy.rules] if policy else []}

    @app.post("/v1/policies/activate")
    def activate_policy(body: PolicyActivation, _: Annotated[Principal, Depends(operator)]) -> dict:
        try:
            policy = load_policy_bytes(body.yaml.encode("utf-8"))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid policy") from None
        policies.activate(policy)
        evaluator.policy = policy
        return {"active_policy_hash": policy.policy_hash, "version": policy.version}

    @app.post("/v1/approvals/{approval_id}/decision")
    def decide_approval(approval_id: str, body: ApprovalDecision,
                        _: Annotated[Principal, Depends(operator)]) -> dict:
        if not approvals.decide(approval_id, body.approve):
            raise HTTPException(status_code=404, detail="approval unavailable")
        return {"status": "approved" if body.approve else "denied"}

    @app.get("/v1/audit")
    def list_audit(_: Annotated[Principal, Depends(operator)],
                   limit: int = Query(default=50, ge=1, le=500),
                   offset: int = Query(default=0, ge=0)) -> dict:
        with db.session() as session:
            total = session.scalar(select(func.count()).select_from(AuditRow)) or 0
            rows = session.scalars(select(AuditRow).order_by(AuditRow.created_at.desc(), AuditRow.id.desc())
                                   .offset(offset).limit(limit)).all()
        return {"total": total, "limit": limit, "offset": offset,
                "items": [{"id": row.id, "created_at": row.created_at, "agent_id": row.agent_id,
                           "case_id": row.case_id, "operation": row.operation, "decision": row.decision,
                           "reason_codes": row.reason_codes, "categories": row.categories,
                           "injection_score": row.injection_score, "privacy_score": row.privacy_score,
                           "policy_hash": row.policy_hash} for row in rows]}
