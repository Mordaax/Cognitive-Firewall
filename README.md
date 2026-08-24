# Cognitive Firewall

Cognitive Firewall is a local firewall for applications that use language models. It checks the content an agent reads, writes, stores, or sends to a provider for personal data, secrets, and instructions hidden in untrusted material.

Agents work with outside material: customer messages, search results, web pages, and tool output. A malicious page can try to redirect the workflow; a customer message can carry private details into a provider request. Cognitive Firewall checks those boundaries before the application continues. Its policy can allow, sanitize, block, or request operator approval.

Repository: [Mordaax/Cognitive-Firewall](https://github.com/Mordaax/Cognitive-Firewall).

## How it works

1. An application submits content with its source, destination, and operation, such as a model input or a tool result.
2. Local detectors check it for supported personal data, secrets, and prompt injection. The active policy decides what may continue.
3. When content can be made safe, the firewall redacts it or replaces personal details with case-scoped pseudonyms. The mapping stays encrypted locally. The included OpenAI and Claude adapters accept only approved model input.
4. The firewall records the decision, scores, and policy version without storing the original content in its audit trail.

The same controls are available through a FastAPI service, Python SDK, MCP server, and command-line tool. An operator dashboard shows redacted activity and approval counts. Re-identifying a pseudonym requires a separate, expiring, single-use approval.

## Run locally

Python 3.12 is required. From the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,full]"
.\.venv\Scripts\python.exe scripts\init_secrets.py
.\.venv\Scripts\python.exe -m uvicorn cognitive_firewall.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

In another terminal, check the service and run the example without a provider key:

```powershell
curl.exe http://127.0.0.1:8000/ready
.\.venv\Scripts\python.exe examples\langgraph_agent.py --provider mock
```

`scripts/init_secrets.py` adds missing local credentials to `.env`. To use a cloud model, set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in that file. Raw personal data is processed locally; the included adapters send only content admitted for the selected provider. Keep `.env` private.

For the container setup, run `docker compose up --build -d`. The API listens on `127.0.0.1:8000` and the dashboard on `127.0.0.1:8501`.

## Try the demo

With the service running, send five synthetic examples:

```powershell
python scripts/demo_requests.py
```

The examples show ordinary content being allowed, an email being replaced with a pseudonym, malicious retrieval being blocked, an email being redacted for export, and a privileged action waiting for approval. These requests exercise the firewall locally; they do not call a model provider.

Open [API docs](http://127.0.0.1:8000/docs) to inspect and try requests. Use **Authorize** with `FIREWALL_AGENT_TOKEN` from your local `.env` for evaluations. Operator endpoints use the separate `FIREWALL_OPERATOR_TOKEN`.

Open the [dashboard](http://127.0.0.1:8501) and unlock it with `FIREWALL_OPERATOR_TOKEN` from `.env` to see decision counts and risk charts. Refresh the page after sending more examples.

## Scope

This is a single-tenant pilot. Its pattern and heuristic detectors can miss unfamiliar personal data or new prompt-injection techniques. Applications must use the guard or API at each boundary they want protected; direct calls to a provider bypass it. See the [security model](docs/security.md) for the full trust boundary and limitations.

## Documentation

- [Architecture](docs/architecture.md)
- [API and CLI](docs/api.md)
- [Operations](docs/operations.md)
