# API and control surfaces

The API base URL is `http://127.0.0.1:8000`. `GET /health` checks process liveness; `GET /ready` checks database and active policy. All `/v1` endpoints require `Authorization: Bearer <token>`.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `POST /v1/evaluations` | agent or operator | Evaluate one boundary request |
| `POST /v1/evaluations/batch` | agent or operator | Evaluate up to 100 requests |
| `GET /v1/policies` | operator | View active version and rule IDs |
| `POST /v1/policies/activate` | operator | Validate and atomically activate YAML |
| `POST /v1/approvals/{id}/decision` | operator | Approve or deny a pending request |
| `GET /v1/audit` | operator | Paginated audit metadata |
| `GET /v1/reports/summary` | operator | Aggregate counts and scores |
| `GET /v1/reports/export` | operator | Redacted JSON export |
| `POST /v1/mappings/reidentify` | operator | Resolve one case-scoped token |

Example evaluation body:

```json
{"operation":"model_input","payload":"alice@example.com","source":"user","destination":"openai","case_id":"demo-1","agent_id":"agent-1"}
```

The response includes `decision`, `safe_payload`, `findings`, `reason_codes`, `injection_score`, `privacy_score`, `policy_hash`, and `audit_id`. `safe_payload` is `null` for blocks and pending approvals. `approval_id` is present on pending approvals; submit the same request plus this ID after operator approval. Request validation errors are generic and never echo the body. OpenAPI is available at `/openapi.json` and `/docs`.

CLI commands: `scan`, `sanitize`, `policy validate`, `report export`, `approval decide`, `mapping reidentify`. `sanitize` writes to a separate output path and supports `--dry-run`. The MCP stdio server exposes `evaluate_content` and `sanitize_content` with the same request and response schemas.
