# Cognitive Firewall + PII-Safe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the approved single-tenant, local-first Cognitive Firewall and PII-Safe design as a working end-to-end v1 today.

**Architecture:** One modular Python evaluation engine owns detectors, policies, transformations, storage, and decisions. FastAPI, SDK, MCP, CLI, and dashboard are adapters over that engine; cloud provider adapters accept only approved transformed content. Protected boundaries fail closed.

**Tech Stack:** Python 3.12, FastAPI/Pydantic, SQLAlchemy with SQLite and Postgres drivers, cryptography, PyYAML, httpx, official Python MCP SDK, Typer, Streamlit, pytest, optional spaCy and Redis, Docker Compose, LangGraph example.

**Spec:** `docs/superpowers/specs/2026-10-22-cognitive-firewall-pii-safe-design.md`

## Global Constraints

- Deploy as one single-tenant service; raw PII stays local and only sanitized content reaches OpenAI or Claude.
- Support every boundary and deliverable listed in the spec. The old twelve-week timeline is irrelevant; all implementation and acceptance gates run today.
- Agent and operator credentials are separate. Only operators approve privileged operations or re-identify a scoped case mapping.
- External model calls pseudonymize email, username, and customer ID within the incident, redact phone and IP, and block detected credentials/API keys. Exports redact all supported PII and block secrets.
- Invalid policy, detector errors, storage errors, failed transformation verification, and missing/altered/expired/reused approvals fail closed.
- No raw payload, secret, key, or re-identification mapping value enters normal logs, audit rows, reports, fixtures committed to Git, or dashboard output.
- Use mocked providers by default; live OpenAI/Claude smoke tests are opt-in with keys from local environment or secret storage.
- Python 3.12 is the execution target on this Windows device. Use exact dependency versions recorded in a lockfile when implementation begins.
- Create and activate `.venv` in Task 1; subsequent `python` commands in this plan run inside that environment.
- The workspace has no Git repository. Initialize Git in Task 1; do not claim commits exist before then.

## File map and ownership

| Files | Responsibility |
|---|---|
| `pyproject.toml`, `.gitignore`, `.env.example`, `README.md` | Package, dependencies, local setup, secret handling |
| `src/cognitive_firewall/schemas.py`, `config.py` | Public models, enums, validated configuration |
| `src/cognitive_firewall/detectors/{injection,pii,secrets}.py` | Pure finding extraction |
| `src/cognitive_firewall/policy/{models,loader,evaluator}.py`, `policies/default.yaml` | Versioned, schema-checked policy decisions |
| `src/cognitive_firewall/transforms/{redaction,pseudonymization,verification}.py` | Safe output and local mapping logic |
| `src/cognitive_firewall/storage/{db,audit,memory,mappings,approvals,policies,reports}.py` | Durable records and expiry |
| `src/cognitive_firewall/{risk,engine}.py` | Scores and shared admission decision |
| `src/cognitive_firewall/api/{app,auth,routes}.py` | Authenticated HTTP contract |
| `src/cognitive_firewall/sdk/{client,guard,providers}.py` | Agent boundary hooks and egress gate |
| `src/cognitive_firewall/mcp/server.py`, `cli/main.py`, `dashboard/app.py` | MCP, batch/operator CLI, telemetry UI |
| `examples/langgraph_agent.py`, `examples/data/` | End-to-end agent and synthetic incident data |
| `Dockerfile`, `compose.yaml`, `alembic/`, `docs/` | Deployment, migration, usage and security documentation |
| `tests/{unit,contract,integration,security}/` | Behavior, adapter parity, and security gates |

## Review Focus

1. Nested JSON with repeated PII: transformation must preserve structure and sanitize every matching path (Task 5 test).
2. Overlapping PII/secret spans: secret handling must win and no raw substring may survive verification (Tasks 3 and 5 tests).
3. Encoded or split instructions in retrieved/tool content: suspicious content must be blocked or quarantined, never silently upgraded to trusted instructions (Task 2 test).
4. Expired memory or approval after a clock boundary: reads and approvals must fail even before background cleanup runs (Tasks 6 and 9 tests).
5. Invalid policy or unavailable audit store while a model call is pending: fail closed before provider invocation (Tasks 4, 8, and 10 tests).

## Today’s critical path and skill routing

Complete Tasks 1–8 for the shared security core, Tasks 9–13 for every integration surface, then Tasks 14–16 for deployment and evidence. Run each task’s focused tests before moving on; run the full suite at the final gate. A failing security gate blocks the claim that the project is complete today.


### Task 1: Repository, package, configuration, and public schemas

**Files:** Create `pyproject.toml`, `.gitignore`, `.env.example`, `README.md`, `src/cognitive_firewall/{__init__,config,schemas}.py`, `tests/unit/test_schemas.py`.

**Interfaces:** Produce `EvaluationRequest`, `Finding`, `Provenance`, `EvaluationResponse`, `Operation`, `DecisionAction`, and `Settings` in `schemas.py`/`config.py`. `EvaluationRequest` includes operation, payload (`str | dict`), source, destination, case_id, agent_id, provenance, and optional approval_id. `EvaluationResponse` includes decision, safe_payload, findings, reason_codes, injection_score, privacy_score, policy_hash, and audit_id.

- [ ] Write `test_request_rejects_missing_case_id_and_oversized_payload` and `test_response_never_serializes_raw_payload_on_block`; assert validation errors contain no submitted text.
- [ ] Run `python -m pytest tests/unit/test_schemas.py -q`; verify failures are for missing models/validation.
- [ ] Initialize Git, create `.venv`, install the package with development dependencies, define schemas/settings, add sample environment names without secret values, and add the first README setup commands. Run `python -m venv .venv`, activate it, then `python -m pip install -e ".[dev]"`.
- [ ] Run `python -m pytest tests/unit/test_schemas.py -q` and `python -m compileall src`; require pass. Commit with `git add . && git commit -m "chore: establish firewall package and contracts"`.

### Task 2: Injection and document-control findings

**Files:** Create `src/cognitive_firewall/detectors/injection.py`, `tests/unit/test_injection.py`, `tests/fixtures/injection.jsonl`.

**Interfaces:** `detect_injection(payload: str | dict, *, source: str) -> list[Finding]`; `Finding` carries category, severity, location, and reason code but no persisted raw match.

- [ ] Write tests for role override, authority spoofing, exfiltration, encoded/split instruction attempts, benign quoted instructions, and untrusted retrieval/tool content; assert findings and locations, including Review Focus 3.
- [ ] Run focused tests and observe expected failures.
- [ ] Implement deterministic patterns plus conservative heuristic scoring. Identify bounded instruction spans for explicit stripping when safe; mark ambiguous suspicious documents for quarantine/block. Preserve source trust labels.
- [ ] Re-run focused tests; commit `feat: detect untrusted instructions`.

### Task 3: Schema-aware PII and secret detection

**Files:** Create `src/cognitive_firewall/detectors/{pii,secrets}.py`, `tests/unit/test_pii_detection.py`, `tests/fixtures/pii.jsonl`.

**Interfaces:** `detect_pii(payload: str | dict) -> list[Finding]`; `detect_secrets(payload: str | dict) -> list[Finding]`. Findings identify JSON path or text offsets and supported category.

- [ ] Write tests for email, phone, IPv4/IPv6, username/customer-ID schema hints, API keys, nested JSON, false-positive examples, and overlapping secret/PII spans; assert secrets retain highest severity (Review Focus 2).
- [ ] Run focused tests and observe expected failures.
- [ ] Implement regex/schema-aware detectors and an optional local spaCy adapter behind configuration; never call a cloud model for classification.
- [ ] Re-run focused tests; commit `feat: detect sensitive data locally`.

### Task 4: Versioned YAML policy engine

**Files:** Create `src/cognitive_firewall/policy/{models,loader,evaluator}.py`, `policies/default.yaml`, `tests/unit/test_policy.py`.

**Interfaces:** `load_policy(path: Path) -> PolicyBundle`; `evaluate_policy(request: EvaluationRequest, findings: list[Finding], policy: PolicyBundle) -> PolicyOutcome`. Bundle includes SHA-256 hash/version; outcome includes action, category transformations, reason codes, and TTL.

- [ ] Write table-driven tests for internal analysis, cloud model, export, memory write, high-risk injection, secret detection, rule precedence, and invalid YAML; assert invalid/absent policy never yields allow (Review Focus 5).
- [ ] Run focused tests and observe expected failures.
- [ ] Implement schema validation, deterministic first-match/priority semantics documented in `policies/default.yaml`, activation hash, and the exact privacy defaults from the spec.
- [ ] Re-run focused tests; commit `feat: evaluate versioned policies`.

### Task 5: Redaction, pseudonyms, and post-transform verification

**Files:** Create `src/cognitive_firewall/transforms/{redaction,pseudonymization,verification}.py`, `tests/unit/test_transforms.py`.

**Interfaces:** `transform_payload(payload: str | dict, findings: list[Finding], outcome: PolicyOutcome, case_id: str, mapping_store: MappingStore) -> str | dict`; `verify_transformation(original_findings: list[Finding], transformed: str | dict, outcome: PolicyOutcome) -> None` raises a closed decision on failure.

- [ ] Write tests for nested/repeated JSON matches, stable in-case tokens, distinct tokens across cases, overlapping secret and PII spans, full export redaction, safe document instruction-span stripping, ambiguous-span blocking, and failed rescan (Review Focus 1–2).
- [ ] Run focused tests and observe expected failures.
- [ ] Implement offset-safe replacement from right to left, JSON-path transformations, bounded instruction-span stripping with trace reason, category-specific case tokens, and post-transform rescan; let secret/block rules override replacement.
- [ ] Re-run focused tests; commit `feat: transform and verify sensitive content`.

### Task 6: Durable audit, memory, mappings, and expiry

**Files:** Create `src/cognitive_firewall/storage/{db,audit,memory,mappings,policies}.py`, `alembic/`, `tests/unit/test_storage.py`.

**Interfaces:** `AuditStore.record(event: AuditEvent) -> str`; `MemoryStore.write(record: MemoryRecord) -> None`, `MemoryStore.read(record_id: str, now: datetime) -> MemoryRecord | None`; `MappingStore.get_or_create(case_id, category, normalized_value) -> str`, `MappingStore.reidentify(case_id, token) -> str`. Implement SQLite and Postgres URLs through SQLAlchemy.

- [ ] Write tests for no raw value in audit rows, case-separated mappings, encrypted mapping column, TTL checked at read before cleanup, and SQLite/Postgres migration parity (Review Focus 4).
- [ ] Run focused tests and observe expected failures; use a disposable Postgres container for parity if Docker is ready.
- [ ] Implement migrations and repositories; derive mapping lookup from keyed HMAC and encrypt reversible values with an environment-provided AES-GCM key. Add optional Redis cache only for nonsensitive derived data.
- [ ] Re-run storage tests and migration checks; commit `feat: persist sanitized decisions and scoped memory`.

### Task 7: Risk scores and shared evaluator

**Files:** Create `src/cognitive_firewall/{risk,engine}.py`, `tests/unit/test_engine.py`.

**Interfaces:** `score_findings(findings: list[Finding]) -> tuple[int, int]`; `Evaluator.evaluate(request: EvaluationRequest) -> EvaluationResponse` with injected detector, policy, transform, store, and clock dependencies.

- [ ] Write golden tests for allow, sanitize, block, and require_approval; assert separate 0–100 scores, block precedence, safe_payload only on allowed decisions, policy hash, and audit ID.
- [ ] Run focused tests and observe expected failures.
- [ ] Compose validation → detection → policy → transformation → verification → audit. Catch dependency errors into stable fail-closed reason codes without echoing payloads.
- [ ] Re-run focused tests; commit `feat: enforce one admission decision`.

### Task 8: Fail-closed and provenance hardening

**Files:** Modify `src/cognitive_firewall/engine.py`; create `tests/security/test_fail_closed.py`, `tests/security/test_provenance.py`.

**Interfaces:** Keep `Evaluator.evaluate` unchanged; mark trusted system prompt identity separately from untrusted context. Audit the source, destination, and decision trace without raw content.

- [ ] Write tests for detector exception, absent policy, invalid policy activation, unavailable audit store before provider call, source trust spoofing, and untrusted content claiming to be a system prompt (Review Focus 5).
- [ ] Run focused tests and observe expected failures.
- [ ] Close every failure path, validate provenance fields against caller role, and use policy-controlled quarantine metadata for suspicious retrieved/tool content.
- [ ] Re-run security tests; commit `fix: close evaluation failure paths`.

### Task 9: Authentication and operator approvals

**Files:** Create `src/cognitive_firewall/storage/approvals.py`, `src/cognitive_firewall/api/auth.py`, `tests/security/test_auth_approvals.py`.

**Interfaces:** `require_role(authorization: str, role: Literal['agent','operator']) -> Principal`; `ApprovalStore.create(binding: ApprovalBinding, expires_at: datetime) -> str`; `ApprovalStore.consume(approval_id: str, binding: ApprovalBinding, now: datetime) -> bool`.

- [ ] Write tests for wrong/missing role, single-use approval, payload/case/policy mismatch, expiry before cleanup, evaluator resubmission with an approved ID, and no operator token in logs (Review Focus 4).
- [ ] Run focused tests and observe expected failures.
- [ ] Implement separate constant-time checked credentials from environment and opaque approval IDs bound to digest, case, operation, and policy version; make `Evaluator.evaluate` consume a valid approval on exact resubmission and persist approval/denial/use audit events.
- [ ] Re-run security tests; commit `feat: authorize operators and bind approvals`.

### Task 10: FastAPI contract and management endpoints

**Files:** Create `src/cognitive_firewall/api/{app,routes}.py`, `tests/contract/test_api.py`.

**Interfaces:** `POST /v1/evaluations`, `POST /v1/evaluations/batch`, `GET /v1/policies`, `POST /v1/policies/activate`, `GET /v1/audit`, `GET /v1/reports/export`, `POST /v1/approvals/{id}/decision`, `GET /health`, `GET /ready`. API returns response schemas and paginated collections; operator endpoints require operator role.

- [ ] Write TestClient tests for all routes, auth matrix, pagination, batch parity, invalid JSON, raw-payload-free errors, and audit outage returning a closed decision (Review Focus 5).
- [ ] Run focused tests and observe expected failures.
- [ ] Mount authenticated routes, OpenAPI examples, consistent error responses, and readiness checks; ensure policy activation is atomic.
- [ ] Re-run API tests and inspect generated OpenAPI; commit `feat: expose authenticated firewall API`.

### Task 11: Python SDK and provider egress gate

**Files:** Create `src/cognitive_firewall/sdk/{client,guard,providers}.py`, `tests/contract/test_sdk.py`, `tests/security/test_provider_egress.py`.

**Interfaces:** `FirewallClient.evaluate(request: EvaluationRequest) -> EvaluationResponse`; `AsyncFirewallClient.evaluate(...)`; `AgentGuard.before_model/before_tool/after_tool/before_memory_write/after_memory_read/after_model/before_export(...)`; `ApprovedPayload` opaque wrapper accepted by `OpenAIAdapter.send` and `ClaudeAdapter.send`.

- [ ] Write tests that mocked provider calls receive only sanitized payloads; direct raw-string provider calls, unavailable API, blocked decisions, and failed transformation never invoke providers.
- [ ] Run focused tests and observe expected failures.
- [ ] Implement sync/async HTTP clients, boundary hooks, correlation IDs, and provider adapters that require `ApprovedPayload` created only from an allow/sanitize decision.
- [ ] Re-run SDK/security tests; commit `feat: guard agent and model boundaries`.

### Task 12: MCP server and batch/operator CLI

**Files:** Create `src/cognitive_firewall/mcp/server.py`, `src/cognitive_firewall/cli/main.py`, `tests/contract/{test_mcp,test_cli}.py`.

**Interfaces:** MCP stdio tools `evaluate_content` and `sanitize_content` use `EvaluationRequest`/`EvaluationResponse`; CLI commands `scan`, `sanitize`, `policy validate`, `report export`, `approval decide`, and `mapping reidentify` call the service/engine under their required role.

- [ ] Write contract tests asserting MCP/CLI outputs match API golden fixtures, unauthorized re-identification fails, dry-run leaves source unchanged, and output paths are separate.
- [ ] Run focused tests and observe expected failures.
- [ ] Implement Python MCP SDK stdio transport and Typer commands; check tool schemas and JSON-RPC behavior with the MCP inspector when available.
- [ ] Re-run contract tests; commit `feat: add MCP and batch control surfaces`.

### Task 13: Dashboard, aggregation, and sanitized reports

**Files:** Create `src/cognitive_firewall/dashboard/app.py`, `src/cognitive_firewall/storage/reports.py`, `tests/contract/test_reports.py`, `tests/integration/test_dashboard.py`.

**Interfaces:** `ReportStore.agent_summary(agent_id, window) -> AgentSummary`; `ReportStore.export_redacted(filters) -> bytes`. Dashboard reads operator-authenticated API endpoints only.

- [ ] Write tests for blocked-event trends, agent-level risk aggregation, policy version display, pagination, export redaction, and no raw/mapping values in rendered dashboard data.
- [ ] Run focused tests and observe expected failures.
- [ ] Implement Streamlit dashboard and CSV/JSON sanitized report export; show counts and separate injection/privacy score trends.
- [ ] Re-run report/dashboard tests; commit `feat: show safe cognitive telemetry`.

### Task 14: LangGraph example and both cloud providers

**Files:** Create `examples/langgraph_agent.py`, `examples/data/synthetic_incident.json`, `tests/integration/test_langgraph_agent.py`.

**Interfaces:** Example accepts `--provider mock|openai|claude`, sends a synthetic incident through retrieval, model, tool, memory, and export hooks, and prints audit IDs/decisions without raw sensitive content.

- [ ] Write a mocked end-to-end test asserting each supported boundary is evaluated, malicious RAG/tool output is blocked, memory TTL works, and captured model requests contain no raw fixture PII.
- [ ] Run focused test and observe expected failure.
- [ ] Implement the example and opt-in live smoke mode. Read provider keys from environment; never commit or print them.
- [ ] Re-run mocked integration test, then optional live calls if keys are configured; commit `feat: demonstrate guarded LangGraph workflow`.

### Task 15: Docker, database options, cache option, and documentation

**Files:** Create `Dockerfile`, `compose.yaml`, `docs/{architecture,security,operations,api}.md`; update `README.md`, `.env.example`, `pyproject.toml` lockfile.

**Interfaces:** `docker compose up --build` starts API and dashboard with SQLite default, binding published ports to `127.0.0.1`. Compose profiles or documented settings enable Postgres and Redis; neither stores plaintext mapping values.

- [ ] Write smoke assertions for `/ready`, API evaluation, dashboard access, migration on fresh SQLite/Postgres, and Redis outage fallback without allowing protected operations incorrectly.
- [ ] Build and launch the stack; expect smoke failure until configuration and containers exist.
- [ ] Add deployment files, pinned dependencies, startup migrations, secret setup, policy rollback, key rotation, backup/recovery, API examples, and risk limitations.
- [ ] Run `docker compose up --build -d`, smoke tests, and `docker compose down`; commit `chore: package pilot deployment`.

### Task 16: Final security and completion gate

**Files:** Create `tests/security/test_regression_corpus.py`, `docs/verification-2026-10-22.md`; update code/tests only for observed failures.

**Interfaces:** No new public interface. Record command outputs, fixture counts, known misses, false positives, measured latency, and remaining risks.

- [ ] Run formatting/type checks, `python -m pytest -q`, migration tests, contract parity tests, mocked egress capture, MCP inspector, Docker smoke, and the dashboard browser check. Add any observed regression fixture before fixing it.
- [ ] Run the seeded injection/PII corpus and record measured precision/recall and p95 latency; verify zero raw supported fixture PII in captured provider requests and no raw values in audit/report/dashboard.
- [ ] Use `systematic-debugging` for failures, then request a security-focused code review and fix material findings. Verify no secrets are tracked and every expected artifact exists.
- [ ] Re-run the full gate, write the evidence report, and commit `test: verify complete pilot`. Claim completion only if all required gates pass; otherwise list exact failing gates and work remaining.

## Execution handoff

The tasks are ordered around shared interfaces, so **native execution** is the fastest default for this one-day target; a fresh final reviewer should inspect security and contract parity. Subagent-driven execution is available if the user prefers per-task review, at higher coordination cost. Do not begin product implementation until the plan is reviewed as requested by the writing-plans skill.

