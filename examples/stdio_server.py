"""Example running Fayda MCP server over standard I/O (stdio).

This script allows desktop LLM clients (such as Claude Desktop, Cursor, or
Zed) to interact with Fayda identity verification tools locally over stdio.

Usage:
    python examples/stdio_server.py

Claude Desktop configuration (`claude_desktop_config.json`):
    {
      "mcpServers": {
        "fayda": {
          "command": "python",
          "args": ["-m", "examples.stdio_server"],
          "env": {
            "FAYDA_CLIENT_ID": "your_registered_client_id",
            "FAYDA_REDIRECT_URI": "https://your-host.example/auth/callback"
          }
        }
      }
    }
"""

import os
import sys
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.mcp.factory import create_mcp_server
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore


def main() -> None:
    # 1. Load configuration: Use FaydaConfig.from_env() if configured, or sandbox preset
    client_id = os.environ.get("FAYDA_CLIENT_ID", "demo_sandbox_client")
    redirect_uri = os.environ.get("FAYDA_REDIRECT_URI", "http://localhost:8000/auth/fayda/callback")

    if os.environ.get("FAYDA_ISSUER_URL") or os.environ.get("FAYDA_ISSUER"):
        config = FaydaConfig.from_env()
    else:
        # Defaults to Ethiopian Fayda eSignet sandbox
        config = FaydaConfig.sandbox(
            client_id=client_id,
            redirect_uri=redirect_uri,
            signing_key_path=os.environ.get("FAYDA_SIGNING_KEY_PATH"),
        )

    # 2. Initialize verification service with storage contracts
    service = FaydaVerificationService(
        config=config,
        sessions=MemorySessionStore(),
        results=MemoryResultRepository(),
    )

    # 3. Create FastMCP server with explicitly registered tools
    server = create_mcp_server(
        service=service,
        name="fayda-stdio-mcp",
        instructions="Privacy-preserving identity and age checks using Ethiopian National ID (Fayda eSignet).",
    )

    # 4. Run server over standard I/O transport
    # Note: FastMCP.run() defaults to stdio transport
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
