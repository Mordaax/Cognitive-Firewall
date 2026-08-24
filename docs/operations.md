# Single-tenant pilot operations

## First start

Install Python 3.12, create `.venv`, and install `.[dev,full]`. Run `python scripts/init_secrets.py`; it appends only missing firewall credentials to the existing `.env`. Use `python -m uvicorn cognitive_firewall.api.app:create_app --factory --host 127.0.0.1 --port 8000` for local startup. `/ready` returns 200 only when the database and active policy are available. The initial schema is created idempotently at startup with SQLAlchemy metadata; back up data before schema changes.

Docker: `docker compose up --build -d`, then `docker compose ps` and `curl http://127.0.0.1:8000/ready`. The dashboard listens at `127.0.0.1:8501`. `docker compose down` stops the containers and retains the named data volume. Do not use `down -v` unless data deletion is intended.

## Optional Postgres and Redis

To use Postgres, set `FIREWALL_POSTGRES_PASSWORD` to a strong secret and `FIREWALL_DATABASE_URL=postgresql+psycopg://firewall:<password>@postgres:5432/firewall` in `.env`; then start `docker compose --profile postgres up --build -d`. Protect `.env` and avoid copying commands into shared logs. To enable Redis report caching, set `FIREWALL_REDIS_URL=redis://redis:6379/0` and start `docker compose --profile redis up --build -d`. A Redis outage yields a cache miss and the report reads the database; admission decisions never consult Redis.

## Policy and approvals

Validate a file with `cognitive-firewall policy validate policies/default.yaml`. Activate YAML through the operator endpoint and save the previous policy file/hash. Roll back by submitting the previous YAML. Each decision response records the active hash; a policy change invalidates pending approvals because the binding includes that hash. Approvals expire after 15 minutes and cannot be replayed.

## Backup, recovery, and keys

Back up the SQLite/Postgres database and `.env` in separate access-controlled locations. For SQLite, stop API writes and copy the database file or use SQLite's online backup API. For Postgres, use `pg_dump` and a tested restore process. Restore the database and original mapping/HMAC keys together, then start the service and check `/ready` plus a synthetic evaluation. Rotate agent/operator tokens by replacing their `.env` values and restarting all API/dashboard processes. Mapping/HMAC key rotation needs a database migration that decrypts and reencrypts mappings; do not rotate those keys in place without that migration.

## Verification

Run `.\.venv\Scripts\python.exe -m pytest -q`, Ruff, and the synthetic LangGraph example. The Docker smoke gate requires Docker Desktop's Linux engine running. Check that provider request capture contains only pseudonyms/redactions, and that audit/report/dashboard outputs contain no raw fixture PII. The verification report documents measured results and any unavailable gates.
