# Defense in depth for agent boundaries

Approved scope: implement all phases requested in the conversation on 2026-10-24.

## Trust model

The trusted host owns agent credentials, tool registrations, resource permissions,
the original task, and executor implementations. Retrieved text, model outputs,
and reader outputs never grant permissions. Hostile Python running in the trusted
broker's process is outside the boundary: use OS/container separation in deployment.

## Deliverables

1. A deny-by-default structured tool registry with JSON Schema validation,
   per-agent tool grants, exact recipient/host constraints and resolved path roots.
   The API binds identities to credentials. Unknown tools and invalid arguments
   block. The existing operator approval binding covers registered sensitive tools.
2. Server-issued, authenticated provenance references bind content, case and agent,
   expire, and retain untrusted status. Derived content cannot erase its lineage.
   Untrusted-derived durable memory and actions require operator approval.
3. An executor broker re-evaluates exact structured actions immediately before
   dispatch, accepts only host-registered callbacks and never evaluates arbitrary
   code. A separate local reader process accepts text and emits schema-validated
   data, has no provider/agent/operator credentials and no registered tools.
   This process is credential isolation, not a complete OS sandbox.
4. Optional local semantic injection classification through a pinned, preinstalled
   Transformers model. Inference has no network downloads, truncation bypass, or
   silent allow on errors. Threshold crossings block; errors fail closed when
   enabled. Disabled mode is reported/documented honestly. Add bounded Unicode
   and encoding inspection without rewriting safe original content incorrectly.
5. Regression tests for hostile and benign fixtures; updated README, API,
   architecture, operations and security documentation, example policies and
   examples showing reader-to-broker separation. No paid provider calls required.

## Compatibility and limitations

Tool calls now require structured arguments and registration. Migrate old curl
fixtures and the mock example rather than silently falling back to permissive tool
execution. Existing content-only evaluations remain supported. The old single
agent token is bound to one configured agent ID; additional agent tokens are
configured explicitly and must be distinct from operator credentials.
No text classifier guarantees injection detection or protects model weights,
training data, arbitrary external tools, or direct vendor calls bypassing the broker.

## Verification

Tests must fail before implementation, then pass. Assert side effects are absent
for denied actions, changed approvals, spoofed identities and untrusted lineage.
Use only synthetic data and temporary/in-memory stores. Run full pytest, Ruff,
dependency consistency, mock workflow and live API/dashboard readiness after restart.
