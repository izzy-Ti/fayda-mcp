"""FastMCP server factory registering explicitly authored verification tools."""

from typing import Callable, Optional
from fastmcp import FastMCP
from fayda_mcp.context import CallerContext
from fayda_mcp.service import FaydaVerificationService
from fayda_mcp.mcp.tools import register_tools


def create_mcp_server(
    service: FaydaVerificationService,
    name: str = "fayda-mcp",
    instructions: Optional[str] = None,
    get_context: Optional[Callable[[], CallerContext]] = None,
) -> FastMCP:
    """Create a standalone FastMCP server configured with Fayda verification tools.

    Args:
        service: Initialized FaydaVerificationService instance.
        name: MCP server name.
        instructions: Instructions exposed to LLM clients.
        get_context: Optional callback to resolve caller context per request.
    """
    server_instructions = instructions or (
        "Provides privacy-preserving identity verification tools using Ethiopian "
        "National ID (Fayda eSignet). Never requires citizen biometrics or OTPs."
    )
    server = FastMCP(
        name=name,
        instructions=server_instructions,
    )
    register_tools(server=server, service=service, get_context=get_context)
    return server
