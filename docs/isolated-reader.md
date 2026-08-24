# Isolated reader and trusted execution

`IsolatedReader().read(text)` starts the fixed `sdk/reader_worker.py` with Python
isolated mode (`-I`). The worker receives JSON over stdin and returns a strict
object containing `paragraphs: list[str]` and `facts: list[str]`. Unknown fields,
malformed JSON, worker errors, oversized output and timeouts fail closed with
`ReaderError`. Defaults limit text to 65,536 UTF-8 bytes, output to 131,072 bytes,
and the worker to five seconds. Each result list is limited to 1,024 items.

The supplied worker deterministically splits paragraphs. `facts` is empty; this
is extraction, not semantic sanitization or a local language model. Attack text
may appear verbatim in paragraphs. Extracted data stays untrusted. The planner
must never ingest raw documents; select narrowly needed validated data, screen it
through the firewall, and retain server-issued provenance when deriving actions
or durable memory. Do not concatenate paragraph strings into system instructions.

The worker inherits only Windows runtime directory variables when present and
new temporary-directory variables. It receives no inherited API keys, tokens,
passwords, PATH, HOME or PYTHONPATH, no open nonstandard file handles and no tools.
Its working directory is a fresh temporary folder removed after execution.
`worker_path` is exclusively trusted host configuration, pointing to a fixed local
Python worker implementing this protocol. Never accept it from retrieved text,
model output or API request fields. A host-provided worker is executable trusted
code and must be reviewed. Reader output is always data and is never executed.

This is process and credential separation, **not an OS security sandbox**. The
worker runs with the host user's filesystem and network privileges and may read
files accessible to that user, including credential files outside its working
directory. There are no CPU/memory, network, filesystem ACL or process-tree limits.
The timeout kills the direct worker, not descendants from a custom worker. For
hostile code or stronger isolation, deploy a restricted OS account/container with
filesystem, network, resource and process-tree controls. Do not put credentials
in worker files or command-line arguments.

`ToolBroker(evaluator, handlers, agent_id=..., case_id=...)` is the trusted host dispatch point.
The host registers a destination-to-callback dictionary (copied at construction).
Callbacks take one dictionary of approved arguments. Each execution owns a deep
request snapshot, requires the bound agent, trusted task case and `tool_request`, checks the local
handler registry, and calls the trusted evaluator immediately before dispatch.
Production uses the full `Evaluator` or authenticated `FirewallClient`, with the
server's tool registry, argument schemas, resource restrictions and exact operator
approval checks. Unknown callbacks, denials, approval requirements and evaluator
failures run no handler. The actual returned safe payload is copied and must be
an object identical to the original action arguments. A sanitizer that changes
an action requires a new request and approval; targets are never silently changed.
Sensitive approvals are single-use under the engine. Every execution re-evaluates.

The broker cannot protect against malicious Python in its own process, direct
vendor/tool calls bypassing it, or a trusted callback that violates its contract.
Callbacks must implement only their registered action and enforce filesystem
race and remote resource semantics where relevant. Neither broker nor reader logs
raw input or worker output. Exceptions exposed by host callbacks/evaluators remain
the host application's responsibility.

Run `python examples/isolated_reader.py` for a synthetic attack document, denied
unregistered action, and harmless registered echo. The demo uses a
real in-memory Evaluator, capability registry, provenance and approval stores. The
attack output is blocked by admission. A separate benign reader result retains
lineage, and its derived echo is denied until a synthetic host operator approves
the exact action. No providers or paid calls are used.


