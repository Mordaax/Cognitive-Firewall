# Defense-in-depth verification: 2026-10-24

All work is local. No provider requests or paid model calls were made.

## Automated verification

- 127 pytest cases passed after the new authorization, provenance, reader and
  semantic-adapter regressions and compatibility migrations.
- Ruff passed and `pip check` reported no broken requirements.
- The mock LangGraph example completed all eight boundaries, blocking malicious
  retrieval/tool results and holding tool actions, memory writes and exports for
  approval. It did not approve its own requests.
- The isolated-reader example used the real evaluator and in-memory stores. An
  unregistered action ran no handler; a lineage-derived echo required exact
  synthetic host approval before its harmless callback ran.
- The 50 curl examples were regenerated from measured in-memory evaluations with
  default policies and semantic screening disabled. They retain expected results
  and PowerShell/Bash equivalents. The live classifier can block additional cases.

Tests cover cross-agent HTTP credentials, mixed-agent batches, operator/agent role
separation, unknown tools, schemas, recipients, URL constraints, path traversal and
relative-path ambiguity; exact approval replay/change/tool-policy changes; provenance
content and identity binding, expiry, bounded ancestry, omission and case switching;
memory failure before side effects; semantic errors and context overflow; reader
credentials, Unicode roundtrips, malformed output, output limits and timeout cleanup.

Independent security review identified relative-path ambiguity across evaluator and
executor working directories and Windows locale-encoded reader output. Both were
reproduced with failing regressions and fixed. MCP identity and cross-case lineage
issues identified during integration were also corrected.

## Actual local classifier

ProtectAI DeBERTa prompt-injection v2 was provisioned from revision
`90c9989b1a342275dd0d1a95aad283c04e075671`, safetensors only. Seven runtime files
occupy about 714 MiB; local manifests contain hashes. Offline CPU smoke inference
completed successfully; see [model details and measured scores](semantic-screening.md).
These fixtures verify operation, not population-level accuracy.

## Running HTTP service

API `http://127.0.0.1:8000/ready` returned `ready` after restart. Dashboard
`http://127.0.0.1:8501/_stcore/health` returned HTTP 200. Operator-authenticated
security status reported default-deny tool authorization, provenance enabled,
semantic screening enabled at threshold 0.8, and mandatory memory-write approval.

| Live synthetic probe | Observed result |
| --- | --- |
| Explain how rain forms | allow |
| Paraphrased administrator request for confidential prior context | block |
| Role-delimiter spoofing in retrieval | block |
| Unknown destructive tool without attack keywords | block |
| Registered demo restart | require_approval |
| Export after exposure to untrusted input | require_approval |
| Another agent ID under the primary agent token | HTTP 403 |

## Limits of this verification

Docker was not run. No production tool connector, OS sandbox or privileged
deployment was exercised. Reader isolation is credential/process separation, not
filesystem/network isolation. The semantic model has a 512-token context and is
intended for English; oversize inputs fail closed. The suite does not demonstrate
complete injection resistance, training/model integrity or protection for tools
that bypass the broker. Review request volume increases under conservative taint
and mandatory memory review; this is a deliberate behavior change.
