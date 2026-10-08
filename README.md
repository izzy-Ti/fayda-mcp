# Fayda MCP Python Library (`fayda-mcp`)

[![PyPI version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://pypi.org/project/fayda-mcp/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An importable, headless Python library providing Model Context Protocol (MCP) tools and verification services for Ethiopian National ID (Fayda eSignet).

## Key Capabilities

- **Explicit FastMCP Tools**: `start_verification`, `get_verification_status`, `get_verification_result`, `cancel_verification`.
- **Zero Raw Demographic / Biometric Leaks**: Outputs minimal boolean predicates (`identity_verified`, `age_over_18`), strictly forbidding citizen biometrics, OTPs, or demographic dumps from entering LLM contexts.
- **Cryptographic Security**: OIDC PKCE S256, RFC 7523 `private_key_jwt` client assertions, and strict JWT signature/nonce validation.
- **Pluggable Architecture**: Zero mandatory database or web framework runtime dependencies in core; optional extras for FastAPI, Redis, and Neon/PostgreSQL.
- **Multi-Tenant Caller Isolation**: Built-in tenant and principal boundaries ensuring Caller A cannot access Caller B verification records.

---

## Installation

```bash
# Core library (headless FastMCP + Fayda OIDC verification engine)
pip install fayda-mcp

# With optional FastAPI integration
pip install "fayda-mcp[fastapi]"

# Full bundle with Redis and Neon/Postgres adapters
pip install "fayda-mcp[fastapi,redis,postgres]"
```

---

## Quick Start (Sandbox)

```python
import base64
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemorySessionStore, MemoryResultRepository
from fayda_mcp.mcp.factory import create_mcp_server

# Configure your Fayda / eSignet credentials
config = FaydaConfig(
    client_id="YOUR_CLIENT_ID",
    redirect_uri="http://localhost:3000/callback",
    authorization_endpoint="[https://esignet.ida.fayda.et/authorize](https://esignet.ida.fayda.et/authorize)",
    token_endpoint="[https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token](https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token)",
    userinfo_endpoint="[https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo](https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo)",
    issuer="[https://esignet.ida.fayda.et](https://esignet.ida.fayda.et)",
    jwks_uri="[https://esignet.ida.fayda.et/v1/esignet/oauth/v2/jwks.json](https://esignet.ida.fayda.et/v1/esignet/oauth/v2/jwks.json)",
    private_key=base64.b64decode("YOUR_PRIVATE_KEY_B64").decode("utf-8"),
)

service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

server = create_mcp_server(service=service)

if __name__ == "__main__":
    server.run(transport="stdio")
```

---

## Running the Complete Sandbox Flow

Run the included standalone sandbox walkthrough:

```bash
python examples/sandbox_flow.py
```

This runs the entire end-to-end lifecycle (starts verification -> builds authorization link -> simulates citizen callback -> queries status -> retrieves privacy-preserving boolean result -> verifies caller isolation) without editing library internals.

---

## Examples

- **Local Standard I/O (stdio)**: [examples/stdio_server.py](examples/stdio_server.py) (Desktop LLM clients, Claude Desktop, Cursor)
- **Remote HTTP Server**: [examples/remote_http_server.py](examples/remote_http_server.py) (Hosted streamable-HTTP / SSE MCP endpoints with FastAPI)
- **Full Sandbox Walkthrough**: [examples/sandbox_flow.py](examples/sandbox_flow.py)

---

## Documentation

- [Production, Compatibility & Operations Guide](docs/production_guide.md)
- [Architecture & Responsibilities](docs/architecture.md)
- [Configuration Guide & Environment Variables](docs/configuration.md)
- [Callback Wiring & Session Binding](docs/callback_wiring.md)
- [Credential Ownership & Cryptography](docs/credentials.md)
- [Cleanup & Lifecycle Management](docs/cleanup_and_lifecycle.md)
- [Database Migrations](docs/migrations.md)
- [Redis Session Storage](docs/redis_sessions.md)
- [Retention Policy](docs/retention.md)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
