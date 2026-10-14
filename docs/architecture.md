# Fayda MCP Architecture

## Delivery Model

`fayda-mcp` is an importable, headless Python library providing:
1. Typed FastMCP tools and schemas for eSignet OIDC (`start_verification`, `get_verification_status`, `get_verification_result`, `cancel_verification`).
2. Offline QR verification tools (`submit_qr_verification`, `get_qr_verification_result`).
3. Citizen Details Matching tools (`start_details_verification`, `get_details_match_result`) with tri-state outcomes and zero demographic leakage.
4. OIDC PKCE generation and private_key_jwt client assertion support.
5. Cryptographic JWT and JWKS validation for Fayda eSignet.
6. Pluggable storage protocols for sessions, results, temporary expected details, and audit trails.

## Responsibilities

| Component | Owner |
|---|---|
| Typed MCP tools & schemas | `fayda-mcp` library |
| OIDC / PKCE & client assertions | `fayda-mcp` library |
| JWT validation & claim evaluation | `fayda-mcp` library |
| Storage protocols & memory adapter | `fayda-mcp` library |
| MCP hosting & OAuth transport security | Integrating application |
| Fayda RP registration & private key | Integrating application |
| Browser redirect & callback endpoints | Integrating application |
| Redis / Neon infrastructure | Integrating application |
