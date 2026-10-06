"""MCP OAuth authentication and token verification helpers."""

from typing import Optional
from app.core.auth import Principal, validate_bridge_token


async def authenticate_mcp_request(authorization_header: Optional[str]) -> Optional[Principal]:
    """Extract and validate bearer token from MCP request header."""
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None
    token = authorization_header[len("Bearer "):].strip()
    return await validate_bridge_token(token)
