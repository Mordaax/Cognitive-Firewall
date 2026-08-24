# Cognitive Firewall + PII-Safe

A single-tenant, local-first admission layer for agent workflows. It checks prompt injection, PII, and secrets at model, retrieval, tool, memory, and export boundaries. A versioned policy returns `allow`, `sanitize`, `block`, or `require_approval`. Only admitted content can enter the bundled OpenAI and Claude adapters.

## Start locally

Requires Python 3.12. From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,full]"
python scripts\init_secrets.py
.\.venv\Scripts\python.exe -m uvicorn cognitive_firewall.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

`scripts/init_secrets.py` adds missing firewall credentials to `.env` without changing existing values. The app loads `.env` on startup. Configure provider credentials as `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; the existing `OPEN_API_KEY` / `CLAUDE_API_KEY` names are also recognized by the example adapters. No provider key is needed for the firewall API or mock example.

In a second terminal:

```powershell
curl.exe http://127.0.0.1:8000/ready
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe examples\langgraph_agent.py --provider mock
```

Agent and operator API calls use separate bearer tokens from `.env`. The batch CLI uses the agent token. The dashboard uses the operator token. To launch the MCP stdio server, run `python -m cognitive_firewall.mcp.server` from this directory with `.env` configured. Its tools are `evaluate_content` and `sanitize_content`.

## Docker pilot

```powershell
python scripts\init_secrets.py
docker compose up --build -d
docker compose ps
```

The API is at `http://127.0.0.1:8000` and dashboard at `http://127.0.0.1:8501`. Both published ports bind to loopback. See [operations](docs/operations.md) for Postgres, Redis, backup, recovery, and key rotation.

## Documentation

- [Architecture](docs/architecture.md)
- [Security model and limitations](docs/security.md)
- [API and CLI](docs/api.md)
- [Operations](docs/operations.md)
- [Approved design](docs/superpowers/specs/2026-10-22-cognitive-firewall-pii-safe-design.md)
- [Implementation plan](docs/superpowers/plans/2026-10-22-cognitive-firewall-pii-safe.md)
