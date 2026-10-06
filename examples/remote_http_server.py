"""Example running Fayda MCP server over remote HTTP.

Provides an HTTP-hosted MCP endpoint for remote LLM clients along with the
required host callback router to handle Fayda eSignet citizen redirects.

Usage:
    uvicorn examples.remote_http_server:app --host 0.0.0.0 --port 8000

Endpoints exposed:
    - /mcp/v1/messages (or /mcp) : Remote FastMCP endpoint (SSE or streamable-http)
    - /auth/fayda/callback       : OIDC redirect callback endpoint
    - /health                    : Health check endpoint
"""

import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.context import CallerContext, SimpleCallerAdapter
from fayda_mcp.integrations.fastapi import (
    create_callback_router,
    create_combined_lifespan,
    create_fastapi_app,
)
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.schemas import VerificationResult
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

# 1. Load host Relying Party configuration
client_id = os.environ.get("FAYDA_CLIENT_ID", "remote_http_demo_client")
redirect_uri = os.environ.get(
    "FAYDA_REDIRECT_URI", "http://localhost:8000/auth/fayda/callback"
)

if os.environ.get("FAYDA_ISSUER_URL") or os.environ.get("FAYDA_ISSUER"):
    config = FaydaConfig.from_env()
else:
    config = FaydaConfig.sandbox(
        client_id=client_id,
        redirect_uri=redirect_uri,
        signing_key_path=os.environ.get("FAYDA_SIGNING_KEY_PATH"),
    )

# 2. Initialize service with pluggable storage contracts
# (In production, replace memory stores with Redis and Neon/Postgres adapters)
service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

# 3. Host-provided caller authorization adapter
# Resolves caller context per MCP invocation and enforces tenant boundaries
def resolve_caller(request_or_tool_name: str) -> CallerContext:
    # In production, extract authenticated API key or Bearer token from MCP headers
    return CallerContext(
        tenant_id=os.environ.get("DEFAULT_TENANT_ID", "default_tenant"),
        principal_id="remote_agent_client",
        scopes=["verification:create", "verification:read", "verification:cancel"],
    )

caller_adapter = SimpleCallerAdapter(context_resolver=resolve_caller)

# 4. Create FastMCP server
mcp_server = create_mcp_server(
    service=service,
    name="fayda-remote-http-mcp",
    caller_adapter=caller_adapter,
)

# 5. Host session-binding hook
# Mandatory security hook: binds the citizen's browser session (e.g. cookie or session header)
def host_session_binding(request: Request) -> str | None:
    return request.cookies.get("fayda_session_token")

# 6. Optional host on_success redirect hook
# Redirects the citizen to a dashboard or success URL after completed verification
async def on_verification_success(request: Request, result: VerificationResult) -> RedirectResponse:
    # Return 303 See Other redirect to application welcome/dashboard page
    return RedirectResponse(
        url=f"http://localhost:3000/onboarding/complete?request_id={result.request_id}&status={result.status}",
        status_code=303,
    )

# 7. Build integrated FastAPI application with combined lifecycles
app = create_fastapi_app(
    service=service,
    session_binding_hook=host_session_binding,
    mcp_server=mcp_server,
    mcp_path="/mcp",
    on_success=on_verification_success,
    title="Fayda Remote HTTP MCP Server",
    version="1.0.0",
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("examples.remote_http_server:app", host="0.0.0.0", port=8000, reload=True)
