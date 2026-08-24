# API and control surfaces

The API base URL is `http://127.0.0.1:8000`. `GET /health` checks process liveness; `GET /ready` checks database and active policy. All `/v1` endpoints require `Authorization: Bearer <token>`.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `POST /v1/evaluations` | agent | Evaluate one boundary request |
| `POST /v1/evaluations/batch` | agent | Evaluate up to 100 requests |
| `GET /v1/policies` | operator | View active version and rule IDs |
| `POST /v1/policies/activate` | operator | Validate and atomically activate YAML |
| `POST /v1/approvals/{id}/decision` | operator | Approve or deny a pending request |
| `GET /v1/approvals/{id}` | operator | Review sanitized binding details for one pending approval |
| `GET /v1/approvals/pending` | operator | List pending approval details with pagination |
| `GET /v1/audit` | operator | Paginated audit metadata |
| `GET /v1/reports/summary` | operator | Aggregate counts and scores |
| `GET /v1/reports/export` | operator | Redacted JSON export |
| `POST /v1/mappings/reidentify/request` | operator | Request approval bound to a case and mapping token |
| `POST /v1/mappings/reidentify` | operator | Resolve one case-scoped token with an approved, single-use `approval_id` |

Example evaluation body:

```json
{"operation":"model_input","payload":"alice@example.com","source":"user","destination":"openai","case_id":"demo-1","agent_id":"demo-agent"}
```

The response includes `decision`, `safe_payload`, `findings`, `reason_codes`, `injection_score`, `privacy_score`, `policy_hash`, and `audit_id`. `safe_payload` is `null` for blocks and pending approvals. `approval_id` is present on pending approvals; submit the same request plus this ID after operator approval. Request validation errors are generic and never echo the body. OpenAPI is available at `/openapi.json` and `/docs`.

CLI commands: `scan`, `sanitize`, `policy validate`, `report export`, `approval decide`, `mapping request-reidentify`, and `mapping reidentify`. Credentials are read only from `FIREWALL_AGENT_TOKEN` or `FIREWALL_OPERATOR_TOKEN` in the environment; there is no `--token` argument. For re-identification, request an approval, decide it as operator, then supply the approval ID to `mapping reidentify`. `sanitize` writes to a separate output path and supports `--dry-run`. The MCP stdio server exposes `evaluate_content` and `sanitize_content` with the same request and response schemas.

For interactive schema inspection on a development machine, run `mcp dev scripts/mcp_inspector.py:server` after initializing `.env`. The normal stdio entry point remains `python -m cognitive_firewall.mcp.server`.
# Security extension: identity, tools and provenance

Evaluation requests must use the agent identity bound to their bearer token.
`FIREWALL_AGENT_ID` defaults to `demo-agent`. Extra tokens are configured with
`FIREWALL_AGENT_TOKENS`, a private JSON object of agent ID to distinct token. The
operator token is accepted only for operator routes, not evaluations. A mixed-agent
batch is rejected as a whole before any evaluation.

Every `tool_request` requires a JSON object in `payload`, a registered
`destination` in `policies/tools.yaml`, and an explicit grant for the bound agent.
Example: `{"service":"demo"}` for `privileged:restart`. This evaluates the proposed
action only; it never restarts anything. An executor must use `ToolBroker` or enforce
equivalent exact-action checks before its own side effects.

Admitted responses may include `provenance_id`. To reuse the exact content, supply
it as request `provenance_id`; to evaluate derived content, supply parent references
as `lineage_ids` (at most 32). Wrong content, unknown handles, expired references or
cross-agent/case references block. All references remain untrusted. Omitting them
does not clear the agent's persisted exposure state.

`GET /v1/security/status` requires the operator credential and returns the
tool-policy hash, provenance and semantic-screening states, threshold and mandatory
memory-review mode. Approval IDs also bind the tool-policy hash and
provenance fields. Memory writes and untrusted-derived exports/tools require
approval, even without recognized personal data or injection.

The pending-approval endpoint intentionally omits raw arguments. Review the original
action in the trusted host and match its canonical payload digest before approving.
Full contracts and migration examples: [defense in depth](defense-in-depth.md).
