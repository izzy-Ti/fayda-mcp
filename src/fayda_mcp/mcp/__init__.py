"""Fayda MCP tool registration and server factory."""
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.mcp.prompts import register_prompts
from fayda_mcp.mcp.resources import register_resources

__all__ = ["create_mcp_server", "register_prompts", "register_resources"]


