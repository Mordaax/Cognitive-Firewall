# Isolated reader and trusted execution

`IsolatedReader().read(text)` starts the fixed `sdk/reader_worker.py` with Python
isolated mode (`-I`). The worker receives JSON over stdin and returns a strict
object containing `paragraphs: list[str]` and `facts: list[str]`. Unknown fields,
malformed JSON, worker errors, oversized output and timeouts fail closed with
`ReaderError`. Defaults limit text to 65,536 UTF-8 bytes, output to 131,072 bytes,
and the worker to five seconds. Each result list is limited to 1,024 items.

The supplied worker splits paragraphs deterministically and leaves `facts` empty.
It runs no language model and performs no semantic sanitization, so paragraphs
may retain the exact attack text. Keep this data untrusted.

Give the planner only narrowly selected, validated data screened through the
firewall, never raw documents or paragraph strings concatenated into system
instructions. Retain server-issued provenance when deriving actions or durable memory.

The worker inherits only Windows runtime directory variables when present and
new temporary-directory variables. It receives no inherited API keys, tokens,
passwords, PATH, HOME or PYTHONPATH, no open nonstandard file handles and no tools.
Its working directory is a fresh temporary folder removed after execution.
`worker_path` is exclusively trusted host configuration, pointing to a fixed local
Python worker implementing this protocol. Never accept it from retrieved text,
model output or API request fields. A host-provided worker is executable trusted
code and must be reviewed. Reader output is always data and is never executed.

Process separation removes inherited credentials, but does not create an OS
security sandbox. The worker retains the host user's filesystem and network
privileges, including access to readable credential files outside its working
directory. CPU/memory, network, filesystem ACL, and process-tree limits are absent.
The timeout kills only the direct worker; custom-worker descendants may survive.

For hostile code or stronger isolation, use a restricted OS account/container with
filesystem, network, resource, and process-tree controls. Keep credentials out of
worker files and command-line arguments.

`ToolBroker(evaluator, handlers, agent_id=..., case_id=...)` is the trusted host dispatch point.
The host registers a destination-to-callback dictionary (copied at construction).
Callbacks take one dictionary of approved arguments. Each execution owns a deep
request snapshot, requires the bound agent, trusted task case and `tool_request`, checks the local
handler registry, and calls the trusted evaluator immediately before dispatch.
Production uses the full `Evaluator` or authenticated `FirewallClient`, with the
server's tool registry, argument schemas, resource restrictions and exact operator
approval checks. Unknown callbacks, denials, approval requirements and evaluator
failures run no handler. The broker copies the returned safe payload, which must be
an object identical to the original action arguments. A sanitizer that changes
an action requires a new request and approval; targets are never silently changed.
Sensitive approvals are single-use under the engine. Every execution re-evaluates.

The broker cannot protect against malicious Python in its own process, direct
vendor/tool calls bypassing it, or a trusted callback that violates its contract.
Callbacks must implement only their registered action and enforce filesystem
race and remote resource semantics where relevant. Neither broker nor reader logs
raw input or worker output. Exceptions exposed by host callbacks/evaluators remain
the host application's responsibility.

Run `python examples/isolated_reader.py` to try the full cycle without provider
or paid calls. The demo uses an in-memory Evaluator with capability, provenance,
and approval stores. It blocks a synthetic attack document and denies an
unregistered action. A separate benign reader result retains lineage, so its
harmless registered echo remains denied until a synthetic host operator approves
the exact action.


