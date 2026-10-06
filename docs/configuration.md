# Configuration Guide

The `fayda-mcp` library is configured via `FaydaConfig`. It separates Relying Party (RP) credentials from runtime policies and infrastructure adapters.

## Environment Variables

Developers can configure their environment using a `.env` file or environment variables:

| Variable | Description | Example (Sandbox) |
|---|---|---|
| `FAYDA_CLIENT_ID` | Registered Fayda relying party client ID | `acme_service_client_1` |
| `FAYDA_REDIRECT_URI` | Registered callback URL on the host application | `https://my-app.example/auth/fayda/callback` |
| `FAYDA_ISSUER_URL` | Fayda OIDC issuer base URL | `https://esignet.sandbox.fayda.et` |
| `FAYDA_AUTHORIZATION_URL` | Fayda eSignet user authorization endpoint | `https://esignet.sandbox.fayda.et/authorize` |
| `FAYDA_TOKEN_URL` | Fayda token exchange endpoint | `https://esignet.sandbox.fayda.et/v1/esignet/oauth/v2/token` |
| `FAYDA_USERINFO_URL` | Fayda UserInfo claims endpoint | `https://esignet.sandbox.fayda.et/v1/esignet/oidc/userinfo` |
| `FAYDA_JWKS_URL` | Fayda public key JWKS endpoint | `https://esignet.sandbox.fayda.et/v1/esignet/oauth/v2/jwks` |
| `FAYDA_SIGNING_KEY_PATH` | Path to host private RSA key for `private_key_jwt` | `/run/secrets/fayda_private_key.json` |
| `FAYDA_SESSION_TTL_SECONDS` | TTL for pending OIDC state & PKCE verifiers (default: 600s) | `600` |
| `FAYDA_RESULT_TTL_SECONDS` | TTL for completed verification results (default: 900s) | `900` |

---

## Loading Configuration

### 1. From Environment (`FaydaConfig.from_env()`)

Loads standard environment variables with prefix `FAYDA_`:

```python
from fayda_mcp import FaydaConfig

config = FaydaConfig.from_env()
```

### 2. Sandbox Preset (`FaydaConfig.sandbox()`)

Quickly pre-populates official Ethiopian Fayda eSignet sandbox endpoints:

```python
from fayda_mcp import FaydaConfig

config = FaydaConfig.sandbox(
    client_id="your_sandbox_client_id",
    redirect_uri="http://localhost:8000/auth/fayda/callback",
    signing_key_path="secrets/fayda_private_key.pem",
)
```

### 3. Explicit Production Configuration

```python
from fayda_mcp import FaydaConfig

config = FaydaConfig(
    client_id="prod_client_id",
    redirect_uri="https://app.example.com/auth/fayda/callback",
    issuer="https://esignet.ida.fayda.et",
    authorization_endpoint="https://esignet.ida.fayda.et/authorize",
    token_endpoint="https://esignet.ida.fayda.et/v1/esignet/oauth/v2/token",
    userinfo_endpoint="https://esignet.ida.fayda.et/v1/esignet/oidc/userinfo",
    jwks_uri="https://esignet.ida.fayda.et/v1/esignet/oauth/v2/jwks",
    signing_key_path="/run/secrets/fayda_key.pem",
    session_ttl_seconds=300,
    result_ttl_seconds=600,
)
```
