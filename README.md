# Fayda MCP Python Library (`fayda-mcp`)

Importable Python package exposing standardized Model Context Protocol (MCP) tools and reusable verification services for Ethiopian National ID (Fayda eSignet).

## Installation

```bash
# Core package (standalone FastMCP + Fayda OIDC verification)
pip install fayda-mcp

# With optional adapters (FastAPI, Redis, PostgreSQL/Neon)
pip install "fayda-mcp[fastapi,redis,postgres]"
```

## Quick Start

```python
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemorySessionStore, MemoryResultRepository

config = FaydaConfig(
    client_id="my-client-id",
    redirect_uri="https://my-app.example/auth/callback",
    issuer="https://esignet.fayda.et",
    authorization_endpoint="https://esignet.fayda.et/authorize",
    token_endpoint="https://esignet.fayda.et/oauth/token",
    userinfo_endpoint="https://esignet.fayda.et/oidc/userinfo",
    jwks_uri="https://esignet.fayda.et/jwks.json",
)

service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)
```

## Running MCP Tools

```python
from fayda_mcp.mcp.factory import create_mcp_server

# Build a standalone FastMCP server wired with verification tools
server = create_mcp_server(service=service)
server.run()
```
