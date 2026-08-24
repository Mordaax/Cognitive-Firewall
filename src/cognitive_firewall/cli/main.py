"""Local-only file scanning and authenticated operator commands."""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer

from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import EvaluationRequest, Operation

app = typer.Typer(no_args_is_help=True)
policy_app = typer.Typer(no_args_is_help=True)
approval_app = typer.Typer(no_args_is_help=True)
report_app = typer.Typer(no_args_is_help=True)
mapping_app = typer.Typer(no_args_is_help=True)
app.add_typer(policy_app, name="policy")
app.add_typer(approval_app, name="approval")
app.add_typer(report_app, name="report")
app.add_typer(mapping_app, name="mapping")


def _local_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise typer.BadParameter("firewall API must be on loopback")
    return base_url


def _api(
    method: str, path: str, *, base_url: str, token: str, json_body: dict | None = None
) -> dict:
    base_url = _local_url(base_url)
    if not token:
        raise typer.BadParameter("credential required")
    try:
        with httpx.Client(
            base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=10
        ) as client:
            response = client.request(method, path, json=json_body)
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise typer.Exit(code=1) from exc


def _credential(role: str) -> str:
    name = "FIREWALL_AGENT_TOKEN" if role == "agent" else "FIREWALL_OPERATOR_TOKEN"
    token = os.environ.get(name, "")
    if not token:
        raise typer.BadParameter(f"{name} environment variable required")
    return token


def _evaluate(request: EvaluationRequest, base_url: str, token: str) -> dict:
    return _api(
        "POST",
        "/v1/evaluations",
        base_url=base_url,
        token=token,
        json_body=request.model_dump(mode="json"),
    )


def _file_request(
    path: Path, case_id: str, agent_id: str, destination: str, operation: Operation
) -> EvaluationRequest:
    return EvaluationRequest(
        operation=operation,
        payload=path.read_text(encoding="utf-8"),
        source="file",
        destination=destination,
        case_id=case_id,
        agent_id=agent_id,
    )


@app.command()
def scan(
    path: Path,
    case_id: str = "default",
    agent_id: str = "cli",
    destination: str = "internal",
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    """Evaluate a local file and print a raw-content-free decision summary."""
    _local_url(base_url)
    result = _evaluate(
        _file_request(path, case_id, agent_id, destination, Operation.RETRIEVAL),
        base_url,
        _credential("agent"),
    )
    typer.echo(
        json.dumps(
            {
                key: result.get(key)
                for key in ("decision", "reason_codes", "audit_id", "policy_hash")
            }
        )
    )


@app.command()
def sanitize(
    source: Path,
    output: Path,
    case_id: str = "default",
    agent_id: str = "cli",
    destination: str = "internal",
    base_url: str = "http://127.0.0.1:8000",
    dry_run: bool = False,
) -> None:
    """Write admitted content to a separate path; dry run only reports the decision."""
    _local_url(base_url)
    if source.resolve() == output.resolve():
        raise typer.BadParameter("output path must differ from source")
    result = _evaluate(
        _file_request(source, case_id, agent_id, destination, Operation.EXPORT),
        base_url,
        _credential("agent"),
    )
    if result.get("decision") not in {"allow", "sanitize"} or result.get("safe_payload") is None:
        raise typer.Exit(code=2)
    if not dry_run:
        content = result["safe_payload"]
        output.write_text(
            content if isinstance(content, str) else json.dumps(content), encoding="utf-8"
        )
    typer.echo(
        json.dumps(
            {"decision": result["decision"], "audit_id": result.get("audit_id"), "dry_run": dry_run}
        )
    )


@policy_app.command("validate")
def policy_validate(path: Path) -> None:
    """Validate a policy file without activating it."""
    policy = load_policy(path)
    typer.echo(json.dumps({"version": policy.version, "policy_hash": policy.policy_hash}))


@approval_app.command("decide")
def approval_decide(
    approval_id: str,
    approve: bool = typer.Option(False, "--approve"),
    deny: bool = typer.Option(False, "--deny"),
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    """Approve or deny one pending request with operator credentials."""
    if approve == deny:
        raise typer.BadParameter("choose exactly one of --approve or --deny")
    result = _api(
        "POST",
        f"/v1/approvals/{approval_id}/decision",
        base_url=base_url,
        token=_credential("operator"),
        json_body={"approve": approve},
    )
    typer.echo(json.dumps(result))


@report_app.command("export")
def report_export(
    output: Path,
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    """Export redacted telemetry to a local JSON file."""
    result = _api("GET", "/v1/reports/export", base_url=base_url, token=_credential("operator"))
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    typer.echo(str(output))


@mapping_app.command("reidentify")
def mapping_reidentify(
    case_id: str,
    token_value: str,
    approval_id: str,
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    """Resolve a case-scoped mapping after a single-use operator approval."""
    result = _api(
        "POST",
        "/v1/mappings/reidentify",
        base_url=base_url,
        token=_credential("operator"),
        json_body={"case_id": case_id, "token": token_value, "approval_id": approval_id},
    )
    typer.echo(result["value"])


@mapping_app.command("request-reidentify")
def mapping_request_reidentify(
    case_id: str,
    token_value: str,
    base_url: str = "http://127.0.0.1:8000",
) -> None:
    """Request a short-lived approval for one case-scoped mapping."""
    result = _api(
        "POST",
        "/v1/mappings/reidentify/request",
        base_url=base_url,
        token=_credential("operator"),
        json_body={"case_id": case_id, "token": token_value},
    )
    typer.echo(json.dumps(result))
