"""Example mounting Fayda FastMCP server into FastAPI with callback route."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.integrations.fastapi import create_callback_router

# 1. Developer config
config = FaydaConfig(
    client_id="demo-client",
    redirect_uri="http://localhost:8000/auth/fayda/callback",
    issuer="https://esignet.sandbox.fayda.et",
    authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
    token_endpoint="https://esignet.sandbox.fayda.et/oauth/token",
    userinfo_endpoint="https://esignet.sandbox.fayda.et/oidc/userinfo",
    jwks_uri="https://esignet.sandbox.fayda.et/jwks.json",
)

# 2. Service
service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

# 3. FastMCP server and HTTP app
mcp_server = create_mcp_server(service=service)
mcp_app = mcp_server.http_app(path="/mcp", transport="streamable-http")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Service lifecycle combined with FastMCP lifespan
    async with service:
        async with mcp_app.lifespan(app):
            yield


# 4. Host FastAPI application
app = FastAPI(title="Developer Host App", lifespan=lifespan)

# Mount callback route
app.include_router(create_callback_router(service=service))

# Mount MCP streamable HTTP sub-application
app.mount("", mcp_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
