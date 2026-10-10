# Fayda MCP Python Library (`fayda-mcp`)

[![PyPI version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://pypi.org/project/fayda-mcp/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An importable, headless Python library providing Model Context Protocol (MCP) tools and verification services for Ethiopian National ID (Fayda eSignet).

## Key Capabilities

- **Explicit FastMCP Tools**:
  - eSignet OIDC: `start_verification`, `get_verification_status`, `get_verification_result`, `cancel_verification`.
  - Offline QR Code: `submit_qr_verification`, `get_qr_verification_result`.
- **Zero Raw Demographic / Biometric Leaks**: Outputs minimal boolean predicates (`identity_verified`, `age_over_18`, `credential_signature_valid`), strictly forbidding citizen biometrics, OTPs, or demographic dumps from entering LLM contexts.
- **Offline & Edge Verification**: High-density QR verification runs completely offline—requiring **no OIDC callback, no webhook, and no client private signing key** (only authority public key / trust bundle).
- **Physical Credential Security Boundaries**: Physical QR scanning validates issuer provenance and credential integrity, but strictly sets `holder_authenticated=false` and never asserts `identity_verified` without live authentication. Copied/screenshotted QR threat model is enforced fail-closed.
- **Scanner Text First Delivery**: Core library accepts raw ASCII scanner text directly from handheld barcode readers and camera SDKs (image scanning is a separate optional adapter).
- **Cryptographic Security**: OIDC PKCE S256, RFC 7523 `private_key_jwt` client assertions, and RFC 7515 Appendix F RS256 detached JWS signature verification.
- **Pluggable Architecture**: Zero mandatory database or web framework runtime dependencies in core; optional extras for FastAPI, Redis, and Neon/PostgreSQL. Redis remains optional for temporary references and rate limits.
- **Multi-Tenant Caller Isolation**: Built-in tenant and principal boundaries ensuring Caller A cannot access Caller B verification records.

---

## Installation

```bash
# Core library (headless FastMCP + Fayda OIDC + Offline QR verification engine)
pip install fayda-mcp

# With optional FastAPI integration
pip install "fayda-mcp[fastapi]"

# Full bundle with Redis and Neon/Postgres adapters
pip install "fayda-mcp[fastapi,redis,postgres]"
```

---

## Quick Start (Offline QR Verification)

```python
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemoryResultRepository, MemorySessionStore

# 1. Enable QR verification with Fayda authority public key
config = FaydaConfig.sandbox(
    client_id="kiosk_qr_verifier",
    redirect_uri="https://localhost/unused",
    qr_verification_enabled=True,
    qr_key_bundle_path="path/to/fayda_qr_keys.pem",  # or qr_public_key_pem
)

# 2. Initialize service (memory or database storage)
service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

# 3. Submit scanned QR text (no network or callbacks needed)
result = await service.submit_qr_verification(
    qr_text="<raw_scanner_text_from_physical_card>",
    purpose="kyc",
    checks=["credential_signature_valid", "age_over_18"],
)
# Returns minimal filtered agent predicates; demographics and photo are excluded!
print(result.checks)  # {'credential_signature_valid': True, 'age_over_18': True}
print(result.holder_authenticated)  # False (offline scan alone does not prove live presence)
```

---

## Quick Start (OIDC Sandbox)

```python
from fayda_mcp import FaydaConfig, FaydaVerificationService
from fayda_mcp.storage.memory import MemorySessionStore, MemoryResultRepository
from fayda_mcp.mcp.factory import create_mcp_server

# 1. Configure with official Fayda sandbox preset
config = FaydaConfig.sandbox(
    client_id="your_registered_client_id",
    redirect_uri="http://localhost:8000/auth/fayda/callback",
)

# 2. Initialize verification service
service = FaydaVerificationService(
    config=config,
    sessions=MemorySessionStore(),
    results=MemoryResultRepository(),
)

# 3. Create FastMCP server
server = create_mcp_server(service=service)

# 4. Run over stdio (e.g. for Claude Desktop or Cursor)
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

- **Offline QR Verification**: [examples/qr_verification.py](examples/qr_verification.py) (Standalone scanner text verification, minimal agent output, copied QR handling)
- **Local Standard I/O (stdio)**: [examples/stdio_server.py](examples/stdio_server.py) (Desktop LLM clients, Claude Desktop, Cursor)
- **Remote HTTP Server**: [examples/remote_http_server.py](examples/remote_http_server.py) (Hosted streamable-HTTP / SSE MCP endpoints with FastAPI)
- **Full Sandbox Walkthrough**: [examples/sandbox_flow.py](examples/sandbox_flow.py)

---

## Documentation

- [Production, Compatibility & Operations Guide](docs/production_guide.md)
- [QR Credential Profile Specification](docs/qr_profile.md)
- [QR Signed Content & Byte Rules](docs/signed_content.md)
- [QR Trusted Keys & Lifecycle Specification](docs/trusted_keys.md)
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
