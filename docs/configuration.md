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

## Offline QR Verification Configuration

Physical QR credential verification operates offline without OIDC redirects, webhooks, or client private signing keys. It is controlled by the following parameters:

| Configuration Parameter | Environment Variable | Default | Description |
|---|---|---|---|
| `qr_verification_enabled` | `FAYDA_QR_VERIFICATION_ENABLED`, `QR_VERIFICATION_ENABLED`, `QR_ENABLED` | `False` | Master switch. Defaults to `False` for fail-closed security. Must be explicitly enabled. |
| `qr_profile` | `FAYDA_QR_PROFILE`, `QR_PROFILE` | `"v4"` | Target specification profile version. |
| `qr_allowed_profiles` | `FAYDA_QR_ALLOWED_PROFILES`, `QR_ALLOWED_PROFILES` | `["v4"]` | Comma-delimited list of accepted QR specification versions. |
| `qr_key_bundle_path` | `FAYDA_QR_KEY_BUNDLE_PATH`, `QR_KEY_BUNDLE_PATH` | `None` | Path to PEM/JSON bundle containing trusted National ID authority public keys. |
| `qr_public_key_pem` | `FAYDA_QR_PUBLIC_KEY_PEM`, `QR_PUBLIC_KEY_PEM` | `None` | Inline PEM string of the trusted National ID authority public key. |
| `qr_max_text_size_bytes` | `FAYDA_QR_MAX_TEXT_SIZE_BYTES`, `QR_MAX_TEXT_SIZE_BYTES` | `16384` | Maximum allowable scanner text size in bytes to prevent DoS/memory exhaustion. |
| `qr_dob_calendar` | `FAYDA_QR_DOB_CALENDAR`, `QR_DOB_CALENDAR` | `"gregorian"` | Default calendar convention for date of birth (`"gregorian"` or `"ethiopic"`). |
| `qr_confirmed_calendars` | `FAYDA_QR_CONFIRMED_CALENDARS`, `QR_CONFIRMED_CALENDARS` | `["gregorian", "ethiopic"]` | Comma-delimited list of recognized calendars permitted for age evaluations. |

> [!IMPORTANT]
> **Fail-Closed Security**: QR verification is disabled by default (`qr_verification_enabled = False`). Invoking verification tools when disabled raises `QRVerificationDisabledError` to prevent inadvertent acceptance of unconfigured verifiers.

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
    qr_verification_enabled=True,
    qr_key_bundle_path="secrets/fayda_qr_authority.pem",
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
    qr_verification_enabled=True,
    qr_key_bundle_path="/run/secrets/fayda_qr_bundle.pem",
    qr_max_text_size_bytes=16384,
)
```
