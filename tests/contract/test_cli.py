import json
from pathlib import Path

from typer.testing import CliRunner

from cognitive_firewall.cli.main import app


def test_sanitize_dry_run_and_separate_output(tmp_path, monkeypatch):
    source = tmp_path / "incident.txt"
    target = tmp_path / "safe.txt"
    source.write_text("alice@example.com")
    calls = []

    def evaluate(request, base_url, token):
        calls.append(request)
        return {"decision": "sanitize", "safe_payload": "EMAIL_ABC_01", "audit_id": "audit"}

    monkeypatch.setattr("cognitive_firewall.cli.main._evaluate", evaluate)
    runner = CliRunner()
    result = runner.invoke(app, ["sanitize", str(source), str(target), "--case-id", "c1", "--agent-id", "a1", "--token", "token", "--dry-run"])
    assert result.exit_code == 0
    assert not target.exists()
    result = runner.invoke(app, ["sanitize", str(source), str(target), "--case-id", "c1", "--agent-id", "a1", "--token", "token"])
    assert result.exit_code == 0
    assert source.read_text() == "alice@example.com"
    assert target.read_text() == "EMAIL_ABC_01"
    assert len(calls) == 2


def test_cli_rejects_same_output_path_and_remote_firewall(tmp_path):
    source = tmp_path / "incident.txt"
    source.write_text("alice@example.com")
    runner = CliRunner()
    result = runner.invoke(app, ["sanitize", str(source), str(source), "--token", "token"])
    assert result.exit_code != 0
    result = runner.invoke(app, ["scan", str(source), "--token", "token", "--base-url", "https://remote.example"])
    assert result.exit_code != 0
