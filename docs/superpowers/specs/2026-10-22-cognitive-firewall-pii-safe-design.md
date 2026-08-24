# Cognitive Firewall + PII-Safe Design

## Intent

Build a single-tenant, local-first security control layer for Python AI agents. It evaluates every supported data boundary for prompt injection, sensitive information, provenance, and policy before content reaches an LLM, tool, export, or memory store. The two named features share one engine and ship today as a complete functional v1 across API, SDK, MCP, CLI, dashboard, storage, Docker, documentation, and integration examples.

The intended user is a developer operating an agent that analyzes security logs and incident material. The operator can use OpenAI and Claude API keys, but raw PII must remain local and provider requests may contain only content approved after sanitization.

## Goals and completion criteria

1. Evaluate user prompts, retrieved documents, tool requests and results, memory reads and writes, model outputs, and exports through one versioned decision contract.
2. Detect direct and indirect prompt-injection patterns, secrets, and the supported PII categories: email, phone number, IP address, username, and customer identifier. Support structured JSON and free text.
3. Apply YAML policies returning allow, sanitize, block, or require approval. Privacy transformations include redaction and incident-scoped stable pseudonyms.
4. Expose the same engine via FastAPI, Python SDK, MCP server, and batch CLI. Include a LangGraph integration example with OpenAI and Claude provider adapters.
5. Persist sanitized audit records, provenance, policy versions, risk scores, memory TTL, and encrypted re-identification mappings. Show telemetry and export sanitized reports.
6. Run locally and in Docker with SQLite by default, a Postgres option, and optional Redis caching. Include tests and setup/deployment instructions.
7. Demonstrate that raw supported PII and secrets do not appear in captured provider requests, memory writes rejected by policy do not persist, and each adapter returns equivalent decisions for the same fixtures.

Completion today means all listed surfaces function end to end and pass the defined gates. It does not mean that arbitrary prompt injection or every possible PII item is guaranteed detectable. Report measured detector misses, false positives, and remaining security risks honestly.

## Non-goals and anti-goals

- No multi-tenant SaaS, billing, cluster deployment, or legal-compliance certification in v1.
- No LLM-based classifier in the enforcement path: local deterministic and optional local NER checks make the decision, avoiding raw-data egress and external dependency for enforcement.
- No agent-accessible re-identification tool. Only an authenticated operator may re-identify a scoped case mapping, and that action is audited.
- No raw payloads, secrets, mapping values, or API keys in ordinary audit events, telemetry, reports, or checked-in examples.
- No permissive fallback when policy, detector, service, or required storage is unavailable at a protected boundary.

## Constraints and decisions

- Architecture choice made by the user: one modular FastAPI service rather than two services.
- Deployment choice carried from the previous discussion: single-tenant pilot.
- Privacy choice carried from the previous discussion: raw PII stays local; only sanitized content reaches OpenAI or Claude.
- The workspace is empty, with no existing repository or application. Python 3.12, Git, Docker, Node, and pytest are present on the device.
- The earlier twelve-week sequence is replaced by a one-day execution plan with evidence gates, not calendar milestones.

## Approaches considered

### Selected: one modular service with shared engine

A Python package owns schemas, detection, transformations, policy, scoring, storage, and audit. FastAPI, SDK, MCP, CLI, and dashboard call it through explicit interfaces. This minimizes duplicated rules and makes cross-adapter parity testable in one day. Modules remain separable if deployment needs change later.

### Alternative: separate Firewall and PII-Safe services

This gives independent scaling and ownership but requires network coordination, two auth/configuration planes, and harder failure semantics. Those costs add risk to the one-day build without helping the single-tenant pilot.

### Alternative: SDK-only embedded checks

This has the fewest moving parts but cannot satisfy the HTTP API, MCP, centralized audit, and telemetry requirements without later architectural change.

## Trust boundaries and data flow

The trusted operator configures system prompts, policies, detector settings, provider keys, and encryption keys. The agent may encounter untrusted user text, RAG chunks, tool returns, and memory content. The service treats those as data regardless of apparent authority. System prompts are checked for known identity/version; retrieved material cannot modify them.

Each request has an operation (`model_input`, `retrieval`, `tool_request`, `tool_result`, `memory_read`, `memory_write`, `model_output`, or `export`), source and destination, case ID, agent ID, content type, provenance, and payload. The pipeline validates schema and size, detects injection/secrets/PII, evaluates policy, transforms when allowed, rescans transformed output, computes scores, records a sanitized event, and returns one decision. Block outranks transformation. An unverified transformation becomes block. A requirement for human approval returns `require_approval` without performing the operation.

The SDK must intercept before calling a model, before and after tools, before memory writes and after reads, and before displaying/exporting model output. The example agent routes each path through the SDK. A bypass test calls the provider adapter with raw PII and confirms it refuses the call.

## Modules and contracts

- `schemas`: Pydantic request, finding, transformation, decision, provenance, and audit models. Decisions carry reason codes, policy version, injection and privacy scores separately, audit ID, and transformed content only when permitted.
- `detectors`: pattern and heuristic checks for role override, authority spoofing, encoded instruction attempts, exfiltration prompts, and tool-output instructions; regex/schema-aware PII and secret checks; optional local spaCy entity checks. Findings retain offsets or JSON paths without logging raw values.
- `policy`: schema-validated YAML rules matching operation, destination, source trust, category, severity, and case/agent scope. Policies are versioned with hashes. Invalid policy versions cannot activate.
- `transforms`: redact, pseudonymize, strip bounded instruction spans from documents when their offsets are unambiguous, and verify. If an injected instruction cannot be removed without changing the useful document content safely, quarantine or block it. Pseudonyms are stable within one incident and different between incidents. Reversible mappings are encrypted in a separate store and expire under policy.
- `risk`: deterministic, explainable 0-100 injection and privacy scores. Scores support prioritization; explicit policy drives enforcement.
- `storage`: SQLite default, Postgres via configuration, encrypted case mappings, memory records with enforced TTL, sanitized audit events, and policy history. Redis may cache nonsensitive detector/policy data but cannot be the sole source of truth.
- `api`: authenticated `/v1/evaluations`, `/v1/evaluations/batch`, policy and audit read endpoints, report export, health, and readiness. Collection endpoints paginate. Error responses do not echo raw payloads.
- `sdk`: synchronous and asynchronous Python client/guard hooks with configurable fail-closed behavior for protected operations and correlation IDs.
- `mcp`: authenticated evaluate/sanitize tools using the same schemas and engine. Remote MCP authentication must match the selected transport; stdio mode runs under the local operator process.
- `cli`: batch scan/sanitize, dry-run, policy validate, report export, and operator-only scoped re-identification. Raw source files are never overwritten by default.
- `dashboard`: a simple local Streamlit view for decisions, blocked-event trends, agent summaries, policy versions, and sanitized exports; no raw payload or mapping display.
- `providers`: example OpenAI and Claude adapters that accept only an approved decision artifact, never arbitrary text. Live tests are opt-in and read keys from environment or secret storage.

## Policy defaults

- External model calls: redact secrets and high-risk identifiers; pseudonymize permitted person/customer identifiers for internal incident analysis; rescan and block if unsupported raw sensitive content remains.
- Export: fully redact PII and secrets; block requests for raw export.
- Untrusted retrieval/tool content with instruction-override or exfiltration findings: quarantine or block context admission. Preserve source text in local quarantine only if explicitly configured; default to metadata-only audit.
- Memory: reject unsanitized writes, enforce a size limit and a policy TTL on every read, and remove expired records. Only sanitized, provenance-tagged content may persist.
- Privileged tool actions and re-identification: operator approval required. The model cannot self-approve.
- Any detector, policy, mapping, or audit failure at a protected boundary: fail closed with a stable reason code and no raw-payload echo.

### Exact privacy defaults

For internal incident analysis destined for a model, pseudonymize email, username, and customer ID within the case; fully redact phone number and IP address; block a detected credential or API key until the caller removes it. For an export or model output shown outside the incident workspace, fully redact every supported PII category and block any detected secret. Structured fields and matching free-text spans use the same treatment. Explicit policy may be stricter, but cannot permit raw supported PII to reach a cloud provider in this pilot. These are design defaults chosen to preserve investigative linkage without exposing direct contact or network details.

### Authentication and approval

The single-tenant API uses two independently configured bearer credentials: an agent credential for evaluations and an operator credential for policy management, audit/report access, approvals, and scoped re-identification. Compare credentials safely, never log them, and reject absent/invalid roles. The dashboard requires the operator credential. The batch CLI reads credentials from environment or a local secret source, never command-line arguments. The MCP server ships in local stdio mode for the pilot and runs with the invoking process's agent credential; a remotely exposed MCP transport is outside the one-day deployment target until standards-compliant authorization is implemented.

`require_approval` applies only to privileged tool requests and re-identification. The evaluator creates an opaque, expiring approval ID bound to the case, operation, payload digest, and policy version. An operator reviews sanitized metadata and approves or denies it via authenticated API or CLI. The agent resubmits the same operation with the approval ID; the engine checks binding, expiry, and single-use status before allowing it. Approval cannot waive the no-raw-PII-to-cloud rule. Every request, decision, and use is audited. A missing, altered, expired, or reused approval fails closed.

## Validation and risk evidence

Create labelled fixtures for benign and malicious prompts, encoded/multilingual attacks, RAG and tool-output injection, structured/free-text PII, overlapping entities, JSON nesting, malformed input, missing keys, stale policy, expired memory, and storage outage. Test each adapter against the same golden cases. Capture mocked and opt-in live OpenAI/Claude requests to prove sanitization occurs before egress. Run security checks for injection bypass, re-identification authorization, log leakage, and fail-closed behavior. Measure p95 latency and detector precision/recall on the fixture corpus; publish results without claiming universal protection.

End-to-end proof: launch Docker stack; validate policy; sanitize an incident log; run the LangGraph example against a mocked provider and optionally live providers; inspect dashboard/audit; export a redacted report; show denied raw export and expired memory; run unit, contract, integration, and smoke tests.

## Remaining builder choices

The implementer may choose exact library versions compatible with Python 3.12, database migration tooling, the local NER package/model, dashboard styling, and the size/latency limits after measuring the device. Document those choices before implementation. The design fixes external behavior and security semantics; these choices must not weaken them.

