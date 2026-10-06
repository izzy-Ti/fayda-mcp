"""Example mounting Fayda FastMCP server into FastAPI with callback route."""

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.integrations.fastapi import (
    create_callback_router,
    create_combined_lifespan,
)

# 1. Host Fayda Configuration
config = FaydaConfig(
    client_id="demo-client",
    redirect_uri="http://localhost:8000/auth/fayda/callback",
    issuer="https://esignet.sandbox.fayda.et",
    authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
    token_endpoint="https://esignet.sandbox.fayda.et/oauth/token",
    userinfo_endpoint="https://esignet.sandbox.fayda.et/oidc/userinfo",
    jwks_uri="https://esignet.sandbox.fayda.et/jwks.json",
)

# 2. Service instance with storage contracts
service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

# 3. FastMCP server instance
mcp_server = create_mcp_server(service=service)

# 4. Combined lifecycle ensuring both service and MCP lifespans run cleanly
lifespan = create_combined_lifespan(
    service=service,
    mcp_server=mcp_server,
)

# 5. Host FastAPI application
app = FastAPI(title="Developer Host App", lifespan=lifespan)

# Mount MCP endpoint
app.mount("/mcp", mcp_server.http_app())


# 6. Host session-binding hook (extracts cookie or session header)
def host_session_binding(request: Request) -> str | None:
    return request.cookies.get("host_session_token")


# 7. Mount callback router matching host registered redirect URI
app.include_router(
    create_callback_router(
        service=service,
        session_binding_hook=host_session_binding,
        on_success=lambda req, result: {"status": "success", "result": result},
    )
)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
