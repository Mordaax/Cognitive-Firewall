"""MCP stdio server bound to the local evaluation engine."""

from mcp.server import MCPServer

from cognitive_firewall.api.app import create_app
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.schemas import EvaluationRequest, EvaluationResponse


def build_mcp_server(evaluator: Evaluator) -> MCPServer:
    server = MCPServer("Cognitive Firewall")

    @server.tool()
    def evaluate_content(request: EvaluationRequest) -> EvaluationResponse:
        """Evaluate agent content at a named boundary; returns safe payload only when admitted."""
        return evaluator.evaluate(request)

    @server.tool()
    def sanitize_content(request: EvaluationRequest) -> EvaluationResponse:
        """Sanitize content using the active local policy; blocked content has no safe payload."""
        return evaluator.evaluate(request)

    return server


def main() -> None:
    app = create_app()
    build_mcp_server(app.state.evaluator).run()


if __name__ == "__main__":
    main()
