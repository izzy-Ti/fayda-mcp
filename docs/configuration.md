# Configuration Guide

The `fayda-mcp` library is configured via `FaydaConfig`. It separates Relying Party (RP) credentials from runtime policies and infrastructure adapters.

## Portal-to-Library Variable Mapping

Fayda Developer / eSignet portals and OAuth dashboards often use portal-specific or generic field names. Rather than assuming `CLIENT_ID` equals `FAYDA_CLIENT_ID`, the table below documents the precise mapping between Fayda developer portal fields, library environment variables, and fallback variables:

| Fayda / eSignet Portal Field | Recommended Env Variable | Generic / Fallback Variable | Description |
|---|---|---|---|
| Relying Party ID / Client ID | `FAYDA_CLIENT_ID` | `CLIENT_ID` | OIDC client ID issued by Fayda portal |
| Redirect URI / Callback URL | `FAYDA_REDIRECT_URI` | `REDIRECT_URI` | Registered developer callback URL |
| Issuer URL / Base URL | `FAYDA_ISSUER_URL` | `FAYDA_ISSUER`, `ISSUER_URL`, `ISSUER` | OpenID Connect discovery issuer URL |
| User Authorization URL | `FAYDA_AUTHORIZATION_URL` | `FAYDA_AUTHORIZATION_ENDPOINT`, `AUTHORIZATION_URL` | Authorization endpoint |
| Token Endpoint URL | `FAYDA_TOKEN_URL` | `FAYDA_TOKEN_ENDPOINT`, `TOKEN_URL` | OAuth token exchange endpoint |
| UserInfo Claims URL | `FAYDA_USERINFO_URL` | `FAYDA_USERINFO_ENDPOINT`, `USERINFO_URL` | UserInfo claims endpoint |
| Public JWKS URL | `FAYDA_JWKS_URL` | `FAYDA_JWKS_URI`, `JWKS_URL` | JSON Web Key Set endpoint |
| Client Private Key | `FAYDA_PRIVATE_KEY` / `FAYDA_SIGNING_KEY` | `PRIVATE_KEY`, `SIGNING_KEY` | Private key for private_key_jwt client assertions |
| Private Key File Path | `FAYDA_SIGNING_KEY_PATH` | `SIGNING_KEY_PATH` | Path to private key file (.pem or .json) |
| Key ID (kid) | `FAYDA_KEY_ID` | `KEY_ID` | Key identifier header for signed assertions |

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
