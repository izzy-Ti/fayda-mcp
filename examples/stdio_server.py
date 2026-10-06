"""Example running Fayda MCP server over standard I/O (stdio)."""

import asyncio
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore
from fayda_mcp.mcp.factory import create_mcp_server


def main():
    # 1. Developer configures Fayda relying-party settings
    config = FaydaConfig(
        client_id="demo-client",
        redirect_uri="https://developer-app.example/auth/fayda/callback",
        issuer="https://esignet.sandbox.fayda.et",
        authorization_endpoint="https://esignet.sandbox.fayda.et/authorize",
        token_endpoint="https://esignet.sandbox.fayda.et/oauth/token",
        userinfo_endpoint="https://esignet.sandbox.fayda.et/oidc/userinfo",
        jwks_uri="https://esignet.sandbox.fayda.et/jwks.json",
    )

    # 2. Initialize verification service with in-memory storage for demo
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )

    # 3. Create standalone FastMCP server and run over stdio
    server = create_mcp_server(service=service, name="fayda-stdio-mcp")
    server.run()


if __name__ == "__main__":
    main()
