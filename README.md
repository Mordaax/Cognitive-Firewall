# Cognitive Firewall + PII-Safe

Local-first admission control for AI agent context. The shared engine detects prompt injection, PII, and secrets, applies versioned YAML policy, and returns an auditable allow, sanitize, block, or approval decision.

## Development

Use Python 3.12. Create a virtual environment, then install `.[dev,full]`. Copy `.env.example` to `.env` and replace placeholders with locally generated secrets. Never commit `.env`.

Run tests with `python -m pytest -q`. The API, SDK, MCP, CLI, dashboard, Docker setup, and example agent are implemented in subsequent tasks described in `docs/superpowers/plans/2026-10-22-cognitive-firewall-pii-safe.md`.
