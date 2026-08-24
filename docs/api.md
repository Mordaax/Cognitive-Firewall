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

Each evaluation returns `decision`, `safe_payload`, `findings`, `reason_codes`, `injection_score`, `privacy_score`, `policy_hash`, and `audit_id`. A block or pending approval has `safe_payload` set to `null`. Pending requests also return `approval_id`; after operator approval, resubmit the same request with that ID. Validation errors are generic and never echo the body. Inspect the OpenAPI schema at `/openapi.json` or use `/docs` interactively.

The CLI has `scan`, `sanitize`, `policy validate`, `report export`, `approval decide`, `mapping request-reidentify`, and `mapping reidentify`. It reads credentials from the environment using `FIREWALL_AGENT_TOKEN` or `FIREWALL_OPERATOR_TOKEN`, with no `--token` argument.

To re-identify a mapping, request approval, decide it as operator, then pass the approval ID to `mapping reidentify`. For file sanitization, `sanitize` writes to a separate output path and accepts `--dry-run`. MCP exposes `evaluate_content` and `sanitize_content` over stdio using the same request and response schemas.

For interactive schema inspection on a development machine, run `mcp dev scripts/mcp_inspector.py:server` after initializing `.env`. The normal stdio entry point remains `python -m cognitive_firewall.mcp.server`.
# Agent identity, tools and provenance

Every evaluation must match the agent identity bound to its bearer token.
`FIREWALL_AGENT_ID` defaults to `demo-agent`; add identities through
`FIREWALL_AGENT_TOKENS`, a private JSON object mapping agent IDs to distinct tokens.
The operator token works only on operator routes. If a batch mixes agent identities,
the API rejects the whole batch before evaluating anything.

Every `tool_request` requires a JSON object in `payload`, a registered
`destination` in `policies/tools.yaml`, and an explicit grant for the bound agent.
Example: `{"service":"demo"}` for `privileged:restart`. This evaluates the proposed
action only; it never restarts anything. An executor must use `ToolBroker` or enforce
equivalent exact-action checks before its own side effects.

An admitted response may include `provenance_id`. Supply it as request
`provenance_id` when reusing that exact content. For derived content, pass up to 32
parent references as `lineage_ids`. Unknown or expired handles, content mismatches,
and references belonging to another agent or case all block. References remain
untrusted, and omitting them leaves the agent's persisted exposure state intact.

`GET /v1/security/status` requires the operator credential and returns the
tool-policy hash, provenance and semantic-screening states, threshold and mandatory
memory-review mode. Approval IDs also bind the tool-policy hash and
provenance fields. Memory writes and untrusted-derived exports/tools require
approval, even without recognized personal data or injection.

The pending-approval endpoint intentionally omits raw arguments. Review the original
action in the trusted host and match its canonical payload digest before approving.
Full contracts and migration examples: [defense in depth](defense-in-depth.md).
