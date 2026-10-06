"""Integration test verifying server foundation boots, exposes routes, and shuts down cleanly."""

import pytest
from starlette.testclient import TestClient
from app.main import create_app
from app.mcp.server import mcp_server
import app.mcp.tools  # noqa: F401


def test_app_boot_and_routes():
    """Verify that the FastAPI application boots, exposes /health and /mcp, and shuts down cleanly."""
    app = create_app()

    # Using Starlette's TestClient enters the combined lifespan on context entry and exits on context exit
    with TestClient(app, base_url="http://localhost") as client:
        # 1. Health liveness route
        live_resp = client.get("/health/live")
        assert live_resp.status_code == 200
        assert live_resp.json() == {"status": "ok"}

        # 2. Health readiness route
        ready_resp = client.get("/health/ready")
        assert ready_resp.status_code in [200, 503]
        assert "components" in ready_resp.json()

        # 3. OAuth Protected Resource metadata
        oauth_resp = client.get("/.well-known/oauth-protected-resource")
        assert oauth_resp.status_code == 200
        data = oauth_resp.json()
        assert "resource" in data
        assert "authorization_servers" in data
        assert "scopes_supported" in data

        # 4. Streamable HTTP MCP endpoint responds
        # GET without session ID returns 400 Bad Request (expected from FastMCP StreamableHTTP)
        mcp_get = client.get("/mcp")
        assert mcp_get.status_code == 400
        assert "jsonrpc" in mcp_get.json()

        # POST initialize JSON-RPC handshake
        mcp_post = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-suite", "version": "1.0"},
                },
            },
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert mcp_post.status_code == 200
        assert "fayda-bridge" in mcp_post.text


@pytest.mark.asyncio
async def test_explicit_mcp_tools_registered():
    """Verify all explicit FastMCP tools are registered on the standalone server."""
    tools = await mcp_server.list_tools()
    tool_names = [t.name for t in tools]

    assert "start_verification" in tool_names
    assert "get_verification_status" in tool_names
    assert "get_verification_result" in tool_names
    assert "cancel_verification" in tool_names
