# Defense in depth implementation plan

> For agentic workers: use subagent-driven-development for isolated modules and
> review; the primary agent owns shared engine/API integration. Track progress here.

Enforce agent capabilities even when detectors miss prompt injection. Before
dispatch, validate structured authorization and exact approvals. Authenticated
provenance persists across steps, while the isolated reader and optional local
classifier add checks without gaining authority to grant tools.
Tech stack: Python 3.12, FastAPI, Pydantic, SQLAlchemy, jsonschema, Transformers.
Spec: ../specs/2026-10-24-defense-depth-design.md

## Global constraints

- No real credentials or raw payloads in audit logs. No paid model calls.
- Default-deny registered tools; no shell execution in tool dispatch.
- The semantic model is opt-in, local-files-only, and fails closed if unavailable.
- Reader process separation is explicitly not a complete OS sandbox.
- Preserve user README and 50-example work and migrate changed tool examples.

## Tasks and interfaces

- [x] Task 1: authorization (`security/tools.py`, config, auth, engine, routes).
  `ToolRegistry.check(request) -> bool` returns whether a permitted action needs
  approval; invalid or unauthorized calls raise `PermissionError`. YAML schemas
  reject unknown config fields. Tests: unknown tools, identity spoof, recipients,
  path traversal, schemas, exact approval change/replay. First run tests against
  the old API to demonstrate unsafe unknown-tool allow, then implement and retest.
- [x] Task 2: provenance (`security/provenance.py`, schemas, engine).
  `ProvenanceStore.issue(request, content, parent_ids=[]) -> str` and
  `verify(reference, request, content=None)` use SQLite, random handles, expiry,
  agent/case ownership and content binding. Test tamper, cross-case, cross-agent,
  missing/expired references before integration. Parents mark derived data as
  untrusted; supplied trust strings never grant authority.
- [x] Task 3: execution and reader (`sdk/broker.py`, `sdk/reader.py`, example).
  `ToolBroker.execute(request)` re-evaluates through the trusted engine, snapshots
  approved arguments, checks destination and invokes only registered callbacks.
  Reader worker receives JSON stdin under a minimal environment, has a timeout and
  output-size/schema bound. No dynamically executed reader code or model output.
  Tests assert denial prevents actual local side effects, environment contains no
  credentials, malformed output fails closed and timeouts terminate the worker.
- [x] Task 4: screening (`detectors/semantic.py`, injection normalization, tests).
  `LocalSemanticDetector.score(payload) -> float`, pipeline loaded from an absolute
  local path only, explicit label mapping, bounded chunks with full coverage or
  rejection. Offline inference. Test score threshold, long input, malformed labels,
  unavailable runtime, and encoded/Unicode regression cases before implementation.
- [x] Task 5: integrate modules, independent security review, documentation and run.
  Run `python -m pytest -q`, `python -m ruff check .`, `python -m pip check`, and
  mock workflow. Restart only this project's services and check readiness. Document
  strict migration, enforcement scope, classifier provisioning and all limitations.

## Decisions / progress

User approval covers all phases and documentation; proceed without intermediate
approval gates. Each module uses red/green tests. Existing checkout is retained;
all changes remain local and reviewable. No push, publication, or deployment.


Completion checks passed: 127 tests, Ruff, and pip check. Review findings covering
relative paths, Windows UTF-8, MCP identity, and cross-case lineage were fixed.
The offline classifier was provisioned and enabled, then live probes passed after
API/dashboard restart. Documentation and 50-request examples were migrated.
Docker runtime was unavailable; base Compose explicitly disables the optional classifier.
