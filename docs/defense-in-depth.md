# Enforced agent boundaries

The firewall separates detection from authorization. A message can look harmless
and still propose an unauthorized action. A classifier score can block a request;
it cannot grant a tool, expand a filesystem root, authorize a recipient, or approve
a memory write.

## Data flow

1. A trusted host starts a task and supplies its agent and case identity. The HTTP
   credential identifies exactly one agent. The operator credential manages the
   service and cannot submit evaluations. An MCP process is bound to its configured
   agent. In-process SDK callers are trusted host code, not an authenticated boundary.
2. The evaluator checks the host-owned tool registry for every `tool_request`.
   Arguments must be a JSON object matching the registered schema. Unknown tools,
   ungranted agents, additional properties and disallowed targets are blocked.
3. Pattern/encoding detectors, local privacy checks and the optional semantic
   classifier screen content. Blocking decisions cannot be overridden by approval.
4. Server-issued provenance handles bind admitted content to its agent, case,
   canonical content digest, expiry and parent references. They contain no raw text.
5. The trusted broker evaluates the exact action immediately before dispatch. It
   is bound to both agent and case, and can only invoke host-registered callbacks.
   A changed sanitized argument object is rejected rather than silently executed.

## Capability configuration

`policies/default.yaml` controls content handling; `policies/tools.yaml` controls
tool capabilities. They are separate policies. Content-policy activation cannot
grant a tool. Tool configuration is validated and loaded on process startup;
restart the API/broker to apply changes. The tool-policy hash is part of approval
binding, so a changed registry invalidates existing action approvals.

```yaml
tools:
  tool:read_report:
    agents: [reports-agent]
    read_only: true
    input_schema:
      type: object
      properties:
        path: {type: string}
      required: [path]
      additionalProperties: false
    path_fields:
      path: ['C:/Reports/Public']
  tool:send_summary:
    agents: [reports-agent]
    require_approval: true
    input_schema:
      type: object
      properties:
        recipient: {type: string}
        summary: {type: string, maxLength: 2000}
      required: [recipient, summary]
      additionalProperties: false
    recipient_fields:
      recipient: [team@example.com]
```

Omitting `read_only: true` makes a tool require approval even if
`require_approval` is false. Declare a tool read-only only if its actual handler
has no writes, sends, hidden side effects or access outside its granted scope.
Resource fields use dot-separated object paths. Every configured field must be
present and a nonempty string. Path roots must be absolute; paths are resolved
before checking containment. Schemas must forbid extra top-level properties;
close nested object schemas too. Schema references are disallowed, including
remote references; validation never retrieves a schema URL.

`host_fields` maps URL argument fields to exact host allowlists. Only HTTPS on
port 443 is admitted; credentials, fragments, unlisted hosts and private IP
literals are denied. This check does not perform DNS or implement HTTP requests.
The actual network handler MUST validate resolved IPs, pin the validated address,
disable or revalidate redirects and enforce outbound network restrictions. A
filesystem handler MUST prevent symlink/junction replacement between validation
and opening. The registry alone cannot solve those execution-time races.

## Provenance and memory

An admitted evaluation returns `provenance_id`. To reuse exactly that content,
submit the handle in request `provenance_id`; the digest must match `payload`.
For a derived summary, submit parent handles in `lineage_ids` instead. References
expire within 24 hours and cannot cross agents or cases. There are at most 32
parents and at most 1,024 checked ancestry records. No client trust string promotes
content into registered system instructions.

Retrieval, tool results, memory reads, model outputs and explicit lineage mark the
agent as exposed to untrusted content. This state is persisted in the database,
survives restart and applies across cases for up to 24 hours after exposure.
Switching case IDs or omitting parent handles does not clear it. Subsequent tool
actions and exports require operator approval, including read-only tools. This is
deliberately conservative and can require review during unrelated tasks by the
same agent. Use separate least-privilege agent identities for separate workloads.
Case binding in the broker is an additional task boundary, not a model-chosen ID.

Every durable memory write requires approval, even with no recognized attack.
Only admitted, transformed content is persisted. Reading memory does not authorize
tools or future memory writes. The evaluation API's `memory_read` checks content
supplied by the caller; it does not retrieve a record by its ID.

## Exact approvals

Review the original structured action in the trusted host before approving it.
The pending endpoint exposes redacted metadata and a payload digest, not the raw
action. Compute the digest as SHA-256 of UTF-8
`json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))`
and compare it with the review record. The digest alone is not enough to decide
whether an action is appropriate. The operator UI must obtain the original action
from its trusted host, never from an injected document claiming to describe it.

Submit the operator decision, then resubmit the exact evaluation with its
`approval_id`. The binding includes payload, operation, source, destination,
agent, case, provenance, content-policy hash and tool-policy hash. It expires in
15 minutes and can be consumed once. An action that changes during sanitization
is blocked; submit the sanitized action as a new request if it is still desired.
The broker does not retry failed approved callbacks automatically.

## Reader and semantic layers

See [isolated reader](isolated-reader.md) for a runnable reader-to-broker example.
The included reader is a deterministic paragraph extractor, not an LLM that can
prove facts or remove malicious meaning. Its outputs remain untrusted. It runs
in a separate process with a minimal environment and strict input/output bounds,
but requires an OS sandbox for protection from malicious reader code. The
planner should receive validated task-specific facts, not arbitrary reader text
relabeled as trusted instructions.

See [semantic screening](semantic-screening.md) for the optional local classifier,
model provisioning, actual smoke results, context limit and accuracy limitations.
The classifier is local and has no tools. It adds a semantic signal, not authority.
It rejects over-context inputs instead of quietly ignoring their tails. When
enabled, inference failure blocks the request; initialization failure prevents
service startup. When disabled, other controls still enforce permissions.

## Verification and scope

Regression tests cover identity spoofing, unknown tools, schema errors, resource
restrictions, altered/replayed approvals, lineage tampering and omission, case
switching, memory persistence failures, reader credentials, timeouts, malformed
outputs, encoded instructions and classifier failures. An integration example
uses real local storage and a harmless callback without paid provider calls.

This is not protection against hostile code in the trusted broker process, direct
provider/tool calls that bypass it, model-weight changes, poisoned training data,
model extraction or arbitrary adversarial images. Model-level and training-time
attacks require separate artifact integrity, access control and evaluation measures.
False positives and missed injections remain possible.

References: [CTF attack taxonomy](https://github.com/ljagiello/ctf-skills/tree/main/ctf-ai-ml),
[OWASP prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).
