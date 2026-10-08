"""Fayda MCP tool registration and server factory."""
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.mcp.prompts import register_prompts

__all__ = ["create_mcp_server", "register_prompts"]

