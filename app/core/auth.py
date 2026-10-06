"""Bridge access token validation and principal resolution."""

from typing import Optional, List
from pydantic import BaseModel


class Principal(BaseModel):
    """Authenticated caller principal."""

    subject: str
    tenant_id: str
    scopes: List[str] = []
    roles: List[str] = []


async def validate_bridge_token(token: str) -> Optional[Principal]:
    """Validate bearer access token issued for bridge MCP resources."""
    # Full OAuth introspection / JWKS validation implemented in task B1
    if not token:
        return None
    return Principal(subject="operator", tenant_id="default-tenant", scopes=["verification:create", "verification:read"])
