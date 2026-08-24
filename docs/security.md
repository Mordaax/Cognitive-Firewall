# Security model

## Trust boundary

Raw PII stays on the local machine. The local evaluator processes it before cloud provider egress. The bundled SDK and CLI reject non-loopback firewall API URLs unless an explicit test transport is injected. The MCP server uses a local stdio process. Cloud adapters require an `ApprovedPayload` returned from an allow or sanitize decision. This wrapper is a programming guardrail; hostile Python code in the same process can bypass it, so untrusted plugins must run in a separate sandbox.

Agent and operator bearer tokens are distinct and checked with constant-time comparison. Agents can evaluate content. Operators can inspect redacted telemetry, activate policy, review and decide approvals, and reidentify case-scoped mappings. The dashboard asks each viewer for the operator credential before fetching reports. Use TLS and stronger identity management if the service is ever exposed beyond the single-host pilot.

## Protected state

Mappings use AES-GCM with a 256-bit key. HMAC-SHA256 protects lookup digests and case tags. The `.env` file holds keys and is Git ignored and excluded from Docker build context. Back up the database and keys together. Losing the mapping key makes stored mappings unrecoverable. Rotating it requires an explicit migration of encrypted rows; do not simply replace it while existing mappings are needed.

Audit rows and report exports contain decision metadata, scores, categories, and policy hashes. They contain no evaluated payload or mapping values. Operator reidentification requires a separate, expiring, single-use approval bound to the case and mapping token. It returns plaintext only after that approval is consumed and records an audit event. Agent IDs, case IDs, and provenance source IDs are validated as opaque identifiers; sensitive identifiers are rejected.

Approval IDs are random, expire after 15 minutes, and can be consumed once. A changed payload, case, operation, destination, source, agent, or policy version fails exact binding. The operator review endpoint exposes only sanitized binding metadata and a payload digest. Operator approval does not override higher-priority block rules. A policy-independent privacy floor prevents editable policies from permitting supported PII or detected secrets to provider adapters. Provider capabilities are bound to `model_input` and the selected provider.

## Limits

Regex and heuristic detectors can miss obfuscated PII, multilingual identifiers, uncommon secrets, and novel injections. They also flag some benign instructions, so an admitted payload carries no guarantee that arbitrary content is safe. Direct vendor-client calls bypass the SDK.

The pilot supports one tenant without distributed policy synchronization. Before expanding deployment, review false positives and misses with sanitized fixtures, update the policy and detector corpus, and retest.

Never enable verbose HTTP request logging or provider SDK debug logging with live content. Keep the API and dashboard bound to `127.0.0.1` and restrict access to `.env`, SQLite/Postgres data, and backups.
# Additional capability and lineage controls

Authorization is independent of attack detection. HTTP tokens and MCP servers are
bound to agent identities; the operator token cannot submit evaluations. Tool
requests default to deny unless registered with structured schemas and agent
grants. Effectful tools require approval unless the trusted host explicitly marks
them read-only. Resource restrictions are configuration constraints, not a network
proxy or secure filesystem implementation. Executor callbacks must enforce DNS,
redirect, symlink and junction safety at the actual I/O boundary.

Before dispatch, the broker checks admission for the exact action under its bound
agent and case. Hostile Python in the same process can bypass the immutable payload
wrapper, which provides no OS capability boundary. Isolate untrusted code and use
deployment controls to prevent direct tool or provider access outside the broker.

Provenance references are opaque, agent/case-bound, content-bound and expiring.
Persisted untrusted exposure follows an agent across cases for at most 24 hours
after exposure; callers cannot restore trust by omitting references or switching
case IDs. Every durable memory write requires operator review. Approvals bind both
content-policy and tool-policy hashes and the complete submitted provenance. Review
the original action in the trusted host; a digest-only pending record does not
establish that an action is desirable.

The reader strips inherited credentials and validates bounded JSON output. It
still has the OS user's filesystem and network access, so it is not a sandbox.
Paragraph extraction leaves malicious meaning intact and returned strings untrusted.

Optional semantic classification runs locally. When enabled, errors and
over-context inputs fail closed, although no classifier guarantees injection
safety. Attacker text claiming an instruction is quoted cannot lower its severity.

For details and operational costs see [defense in depth](defense-in-depth.md),
[isolated reader](isolated-reader.md) and [semantic screening](semantic-screening.md).
