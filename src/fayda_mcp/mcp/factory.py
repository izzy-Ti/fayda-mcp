"""FastMCP server factory registering explicitly authored verification tools."""

from typing import Any, Callable, Optional
from fastmcp import FastMCP
from fayda_mcp.context import CallerContext
from fayda_mcp.mcp.tools import register_tools
from fayda_mcp.service import FaydaVerificationService


def create_mcp_server(
    service: FaydaVerificationService,
    name: str = "fayda-mcp",
    instructions: Optional[str] = None,
    caller_adapter: Optional[Any] = None,
    get_context: Optional[Callable[[], CallerContext]] = None,
) -> FastMCP:
    """Create a standalone FastMCP server configured with Fayda verification tools.

    Args:
        service: Initialized FaydaVerificationService instance.
        name: MCP server name.
        instructions: Instructions exposed to LLM clients.
        caller_adapter: Host-provided CallerAuthorizationAdapter or context resolver.
        get_context: Legacy optional callback to resolve caller context per request.
    """
    server_instructions = instructions or (
        "Provides privacy-preserving identity verification tools using Ethiopian "
        "National ID (Fayda eSignet). Never requires citizen biometrics or OTPs."
    )
    server = FastMCP(
        name=name,
        instructions=server_instructions,
    )
    register_tools(
        server=server,
        service=service,
        caller_adapter=caller_adapter,
        get_context=get_context,
    )
    return server
