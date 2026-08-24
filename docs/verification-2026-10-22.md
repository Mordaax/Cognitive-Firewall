# Verification: 2026-10-22 pilot

## Scope and setup

Single-tenant Windows host at `H:\CognitiveAIH`, Python 3.12 virtual environment, local SQLite by default, Docker Desktop Linux engine for container checks. The test data is synthetic (`example.com`, documentation IP ranges, and fake credentials). Secrets in `.env` were not printed or committed.

## Security regression results

The labeled corpus has 22 cases covering nested JSON, free-text PII, benign content, direct and encoded instruction attacks, and a known multilingual attack. These case-level metrics apply only to those fixtures. An injection prediction counts as positive at severity 80 or above.

| Detector | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Supported PII | 8 | 0 | 0 | 14 | 1.0000 | 1.0000 |
| High-risk injection | 6 | 0 | 1 | 15 | 1.0000 | 0.8571 |

Warm detector p95 was **0.0174 ms** over 440 paired PII/injection calls on this host. Local evaluator p95 was **0.687 ms** over 220 calls including SQLite audit and mapping work. Both exclude network latency. The known false negative is a Spanish instruction override (`multilingual_override`). The deterministic detector does not establish safety for arbitrary novel, obfuscated, or multilingual content.

Focused regression tests cover: immutable approved JSON snapshots; provider capture for both OpenAI and Claude; object-key and numeric-field denial; a policy-independent privacy floor; operation- and destination-bound provider approval; opaque metadata; single-use, expiring approvals for re-identification; sanitized approval review; policy-bounded mapping expiration; cross-process policy reload; and fail-closed storage and detector paths. Synthetic provider captures contained no raw fixture PII. Audit/report/dashboard checks found no raw fixture PII.

## Integration evidence

- OpenAI and Claude live synthetic LangGraph smoke calls both completed with a `sanitize` model-input decision and eight audited boundaries. No provider response body or credential was printed.
- The MCP SDK contract tests exercise structured tool schemas and JSON-RPC through an in-memory client. `mcp dev scripts/mcp_inspector.py:server` started the local Inspector web endpoint successfully, then was stopped; interactive manual tool execution was not part of the automated gate.
- SQLite startup and active-policy reload are covered by tests. Postgres schema creation was run twice successfully in a disposable Compose profile; Redis cache set/get and outage fallback were exercised.
- The final source ran in a temporary local API and Streamlit stack. The API became ready, blocked a synthetic malicious retrieval, and the browser verified the dashboard viewer gate and trend panels. The script stopped both processes and removed its synthetic SQLite data afterward.
- A previous Docker image passed API readiness, sanitized evaluation, and dashboard browser checks. The final source image could not be rebuilt because Docker Desktop developed a read-only filesystem / I/O error, then failed to start its Linux engine after restart. This is an environment gate, not a passing final-image result.

## Final gates

| Gate | Result |
| --- | --- |
| Ruff lint and format | Passed across `src`, `tests`, `examples`, `scripts` |
| mypy source type check | Passed, 41 source files |
| Full pytest suite | Passed, 64 tests |
| Final Docker Compose build and API `/ready` | Blocked: Docker Desktop Linux engine unavailable after read-only filesystem / I/O error |
| Final dashboard render and viewer login | Passed against final source with `scripts/check_local_stack.py`; final Docker image blocked as above |
| Git secret tracking check | `.env` ignored and untracked; `pip check` passed |

## Operational limits

This single-host pilot can miss unsupported PII patterns and novel attacks. Its SDK depends on cooperative Python callers, since hostile code in the same process can bypass it. Use the approval audit trail and review policy changes before activation. Mappings default to 24-hour retention; [operations.md](operations.md) covers backups and key rotation.

Once Docker Desktop's Linux engine is healthy, run `docker compose up --build -d`, check `http://localhost:8000/ready`, and run `.\.venv\Scripts\python.exe scripts/check_dashboard.py` to close the final container gate. The latest Postgres migration also needs a fresh run in that environment; the corresponding SQLite migration and approval behavior passed automated tests.
