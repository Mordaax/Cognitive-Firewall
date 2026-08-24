"""MCP stdio server bound to the local evaluation engine."""

from mcp.server import MCPServer

from cognitive_firewall.api.app import create_app
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.schemas import EvaluationRequest, EvaluationResponse


def build_mcp_server(evaluator: Evaluator, agent_id: str = "demo-agent") -> MCPServer:
    server = MCPServer("Cognitive Firewall")

    def bound_evaluate(request: EvaluationRequest) -> EvaluationResponse:
        if request.agent_id != agent_id:
            raise PermissionError("agent identity mismatch")
        return evaluator.evaluate(request)

    @server.tool()
    def evaluate_content(request: EvaluationRequest) -> EvaluationResponse:
        """Evaluate agent content at a named boundary; returns safe payload only when admitted."""
        return bound_evaluate(request)

    @server.tool()
    def sanitize_content(request: EvaluationRequest) -> EvaluationResponse:
        """Sanitize content using the active local policy; blocked content has no safe payload."""
        return bound_evaluate(request)

    return server


def main() -> None:
    from cognitive_firewall.config import Settings
    settings = Settings.from_env()
    app = create_app(settings)
    build_mcp_server(app.state.evaluator, settings.agent_id).run()


if __name__ == "__main__":
    main()
