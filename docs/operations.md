# Single-tenant pilot operations

## First start

Install Python 3.12, create `.venv`, and install `.[dev,full]`. Run `python scripts/init_secrets.py`; it appends only missing firewall credentials to the existing `.env`. Use `python -m uvicorn cognitive_firewall.api.app:create_app --factory --host 127.0.0.1 --port 8000` for local startup. `/ready` returns 200 only when the database and active policy are available. The initial schema is created idempotently at startup with SQLAlchemy metadata; back up data before schema changes.

Docker: `docker compose up --build -d`, then `docker compose ps` and `curl http://127.0.0.1:8000/ready`. The dashboard listens at `127.0.0.1:8501` and prompts each browser session for the operator credential before loading reports. `docker compose down` stops the containers and retains the named data volume. Do not use `down -v` unless data deletion is intended.

## Optional Postgres and Redis

To use Postgres, set `FIREWALL_POSTGRES_PASSWORD` to a strong secret and `FIREWALL_DATABASE_URL=postgresql+psycopg://firewall:<password>@postgres:5432/firewall` in `.env`; then start `docker compose --profile postgres up --build -d`. Protect `.env` and avoid copying commands into shared logs. To enable Redis report caching, set `FIREWALL_REDIS_URL=redis://redis:6379/0` and start `docker compose --profile redis up --build -d`. A Redis outage yields a cache miss and the report reads the database; admission decisions never consult Redis.

## Policy and approvals

Validate policy with `cognitive-firewall policy validate policies/default.yaml` before activating YAML through the operator endpoint. Keep the previous file and hash so you can roll back by submitting that YAML. Decisions record the active hash, and changing it invalidates pending approvals.

Review requests through `GET /v1/approvals/pending` or `GET /v1/approvals/{id}` before deciding. Approval expires after 15 minutes and cannot be replayed.

Re-identification requires two steps before the final lookup: submit the case and pseudonym to `/v1/mappings/reidentify/request`, then decide the returned approval ID via `/v1/approvals/{id}/decision`. Submit the same case and pseudonym with `approval_id` to `/v1/mappings/reidentify`. The approval is single-use; mappings expire after 24 hours by default. The CLI reads bearer tokens from environment variables, not command arguments.

## Backup, recovery, and keys

Back up the SQLite/Postgres database and `.env` in separate access-controlled locations. For SQLite, stop API writes and copy the database file or use SQLite's online backup API. For Postgres, use `pg_dump` and a tested restore process. Restore the database and original mapping/HMAC keys together, then start the service and check `/ready` plus a synthetic evaluation. Rotate agent/operator tokens by replacing their `.env` values and restarting all API/dashboard processes. Mapping/HMAC key rotation needs a database migration that decrypts and reencrypts mappings; do not rotate those keys in place without that migration.

## Verification

Run `.\.venv\Scripts\python.exe -m pytest -q`, Ruff, and the synthetic LangGraph example. The Docker smoke gate requires Docker Desktop's Linux engine running. Check that provider request capture contains only pseudonyms/redactions, and that audit/report/dashboard outputs contain no raw fixture PII. The verification report documents measured results and any unavailable gates.
# Operating the stricter boundaries

Install the core `jsonschema` dependency with `pip install -e ".[dev,full]"`
after upgrading. Semantic inference also requires `.[semantic]` and a
reviewed local model, described in [provisioning](semantic-screening.md). Startup
never downloads weights, and fresh clones contain none.

Set `FIREWALL_SEMANTIC_MODEL_PATH` to the model's absolute directory. For the
documented model, use `FIREWALL_SEMANTIC_LABELS=INJECTION` and a probability
threshold such as `FIREWALL_SEMANTIC_THRESHOLD=0.8`. Input beyond its 512-token
context fails closed.

The base Docker image does not install the optional semantic runtime or bundle
weights. Base Compose explicitly disables semantic screening so a host `.env`
containing a Windows model path cannot break container startup. To enable it in a
container, build an image with `.[semantic]`, mount a reviewed model directory
read-only, and override `FIREWALL_SEMANTIC_MODEL_PATH` with its Linux mount path.
The native Windows deployment was tested; Docker runtime validation was unavailable
on this machine. Model directories and local setup files are excluded from builds.

Bind `FIREWALL_AGENT_TOKEN` to `FIREWALL_AGENT_ID` (default `demo-agent`). Configure
additional identities using private JSON `FIREWALL_AGENT_TOKENS`; tokens must be
unique and separate from the operator credential. Update CLI `--agent-id` and curl
bodies to match. The operator token no longer submits evaluations. MCP uses the
configured primary agent identity. Do not expose operator credentials to agents or
reader workers.

`FIREWALL_TOOLS_PATH` defaults to `policies/tools.yaml`. Register only trusted tool
implementations with closed schemas, agent grants and explicit resource limits.
Changes require restarting the API and any in-process broker. Content policy
activation cannot grant tools. Tool-policy hash changes invalidate old action
approvals. Check `GET /v1/security/status` with the operator token after restart.

Startup creates missing provenance and exposure tables idempotently; include
them in database backups. After untrusted input, exposure persists across tasks
for up to 24 hours, increasing review requests. Clearing it to admit an action
bypasses that control. Every memory write requires approval.

Run the 50 curl examples against a synthetic setup; they create pending approvals
but do not execute tools. Expected decisions in the examples assume default
policies and semantic screening disabled; a configured classifier may block more.
The mock LangGraph workflow reports held steps instead of approving them itself.
The separate isolated-reader example contains an explicit synthetic host approval
to demonstrate the full local cycle; never copy automatic approval into production.

## Validation commands

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe examples\langgraph_agent.py --provider mock
.\.venv\Scripts\python.exe examples\isolated_reader.py
```

Before approving a pending action, compare the trusted host's original structured
action with its canonical digest in the review record. Keep original arguments
out of shared logs. An approved callback that fails is not automatically retried;
obtain new approval after checking whether any side effect already occurred.
