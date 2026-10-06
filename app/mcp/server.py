"""Standalone FastMCP server definition."""

from fastmcp import FastMCP
from app.core.config import get_settings

settings = get_settings()

mcp_server = FastMCP(
    name="fayda-bridge",
    instructions="Standardized tools for initiating and checking citizen identity verification via Fayda eSignet.",
)
