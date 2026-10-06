"""Central API router assembling all HTTP routes."""

from fastapi import APIRouter
from app.core.config import get_settings
from app.api.routes import health, onboarding, verification, callback

api_router = APIRouter()

# Register modular routes
api_router.include_router(health.router)
api_router.include_router(onboarding.router)
api_router.include_router(verification.router)
api_router.include_router(callback.router)


@api_router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    """Expose OAuth 2.0 Protected Resource Metadata for MCP clients."""
    settings = get_settings()
    return {
        "resource": settings.MCP_RESOURCE_URL,
        "authorization_servers": [settings.MCP_AUTH_ISSUER],
        "scopes_supported": settings.MCP_REQUIRED_SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{settings.PUBLIC_BASE_URL}/docs",
    }
