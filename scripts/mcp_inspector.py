"""Discoverable local entry point for `mcp dev scripts/mcp_inspector.py:server`."""

from pathlib import Path

from dotenv import load_dotenv

from cognitive_firewall.api.app import create_app
from cognitive_firewall.mcp.server import build_mcp_server

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
server = build_mcp_server(create_app().state.evaluator)
