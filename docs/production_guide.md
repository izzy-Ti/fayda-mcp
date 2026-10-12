# Fayda MCP Production, Compatibility & Operations Guide

This guide documents operational requirements, compatibility guarantees, architectural boundaries, and configuration best practices for deploying `fayda-mcp` in production.

---

## 1. Release Blockers & Security Guarantees

The following security and integrity invariants are strictly enforced across the library:

| Invariant | Guarantee & Enforcement Mechanism |
| :--- | :--- |
| **No silent simulation when keys are missing** | Verification strictly requires a configured Fayda client signing key. If unconfigured or private key is missing during callback exchange, `complete_verification()` raises `ConfigurationError`. Simulated claims or mock tokens are never returned in production paths. |
| **No anonymous-principal bypass for protected results** | Verification requests initiated with an explicit `principal_id` (e.g. `agent-1`) cannot be accessed by callers with `principal_id="anonymous"`. Strict isolation in `_authorize_caller()` raises `AuthorizationError` unless the caller possesses admin scopes (`verification:admin` or `*`). |
| **No cancelled or expired request completion** | Callbacks attempting to complete a request that is cancelled, already finalized, or expired (by status or beyond `session_expires_at` / `expires_at` timestamp) are immediately rejected with `InvalidStateError`. |
| **No true contact flag inferred from field presence** | The presence of a raw phone number or email string in claims **never** infers that the contact is verified. Contact checks (`phone_verified`, `email_verified`) require strict boolean verification flags (`phone_number_verified: true` or documented provider assurance metadata). Missing or malformed flags evaluate to `unavailable`. |
| **No ambiguous-calendar age** | Date-of-birth parsing defaults strictly to ISO 8601 Gregorian (`YYYY-MM-DD`). Ethiopic calendar dates are converted **only** when explicitly configured via `source_calendar="ethiopic"` or documented provider metadata. Ambiguous, partial, or malformed DOB values evaluate to `unavailable` rather than guessing. |
| **No unbounded stale-key acceptance** | Stale JWKS keys are never accepted unconditionally. Host policy enforces bounded stale-while-revalidate with a default stale grace of 0 seconds (`FAYDA_JWKS_STALE_GRACE_SECONDS=0`). Hard-expired keys fail closed until refreshed. Token-supplied `jku` or `x5u` headers and unsigned fallbacks are strictly rejected. |
| **No migration or dotenv side effects at import** | Importing `fayda_mcp` or constructing configuration performs zero database schema DDL operations and does not read `.env` from the current working directory. Environment variables are loaded only when an explicit `--env-file` or host loader is provided. |
| **No credentials in wheel/sdist or logs** | Build targets in `pyproject.toml` strictly exclude `.env*`, `*.pem`, `*.key`, and secret files from source distributions and wheels. All logging, error traces, and config dumps redact private keys, client secrets, and Redis passwords. |

---

## 2. Optional Extras & Dependencies

Core `fayda-mcp` is lightweight and headless, with zero mandatory database or web framework dependencies. Optional capabilities are installed via standard extras:

```bash
# Core headless library (in-memory storage, FastMCP tools)
pip install fayda-mcp

# Redis session storage adapter
pip install "fayda-mcp[redis]"

# PostgreSQL / Neon durable storage and migrations adapter
pip install "fayda-mcp[postgres]"

# FastAPI HTTP server and callback web endpoints
pip install "fayda-mcp[fastapi]"

# Full production bundle
pip install "fayda-mcp[all]"
```

---

## 3. Storage Ownership & Connection Lifecycles

`fayda-mcp` supports two client ownership models for Redis and PostgreSQL connections:

### Library-Owned Connections
Created using factory classmethods (e.g., `RedisSessionStore.from_url(...)`, `PostgresResultRepository.from_url(...)`). The storage adapter manages pool lifecycle and automatically closes socket handles and connection pools when `await service.aclose()` or adapter `.close()` is called.

### Host-Owned Connections
Instantiated by passing pre-existing client instances (e.g., `aioredis.Redis`, SQLAlchemy `AsyncSession` factory) with `owned=False`. The host application maintains complete ownership: `service.aclose()` will **not** close host connection pools, allowing them to be safely shared with other application services.

---

## 4. Explicit Migration Invocation

Database migrations are **never** executed automatically on import or runtime startup. Production database schemas must be migrated explicitly using the CLI or programmatic runner:

### CLI Migrations
```bash
# Check current migration status
fayda-mcp migrate --database-url-env DATABASE_URL --status

# Apply all pending migrations (up to latest version)
fayda-mcp migrate --database-url-env DATABASE_URL

# Roll back the latest migration
fayda-mcp migrate --database-url-env DATABASE_URL --rollback --steps 1
```

### Schema Versioning & Notes for Existing Consumers
- **Version `0001` (`0001_initial_schema`)**:
  - Tables: `fayda_schema_migrations`, `fayda_requests`, `fayda_results`, `fayda_audit_events`.
  - Timestamp columns (`created_at`, `session_expires_at`, `retention_expires_at`, `verified_at`, `result_expires_at`, `occurred_at`) use native `TIMESTAMPTZ`.
  - Check definitions and audit metadata use native `JSONB`.
  - Multi-tenant uniqueness constraint on `(tenant_id, principal_id, idempotency_key)`.

---

## 5. Deployment Modes: CLI Server & Callback Architectures

### Mode A: Local Combined HTTP Mode
In combined HTTP mode, the same service instance serves both the Model Context Protocol endpoint and the registered browser callback:
```bash
fayda-mcp run --transport http --host 127.0.0.1 --port 3000 --env-file .env
```
- MCP endpoint: `http://127.0.0.1:3000/sse` (or streamable HTTP)
- Browser callback: `http://127.0.0.1:3000/callback`

### Mode B: Distributed Multi-Process Architecture
In enterprise deployments, desktop or backend MCP agents run over `stdio`, while callback endpoints run inside dedicated web services. Both processes coordinate safely by sharing Redis and Neon:

```
[ Process A: MCP Agent (stdio) ]
               │
               ▼  (start_verification: saves session in Redis, reserves record in Neon)
     ┌──────────────────┐          ┌───────────────────┐
     │   Redis Cloud    │          │   Neon Database   │
     │  (Session Store) │          │(Durable Repo/Audit│
     └──────────────────┘          └───────────────────┘
               ▲
               │  (complete_verification: GETDEL session, verifies binding, finalizes outcome)
[ Process B: Callback Webhook (HTTP) ]
```

1. **Process A** generates the authorization URL and stores state/nonce in Redis.
2. The citizen completes authentication in the browser and is redirected to **Process B**.
3. **Process B** validates the browser session binding, atomically consumes the state from Redis via `GETDEL` (preventing replay attacks), exchanges the authorization code, and finalizes the result into Neon.
4. **Process A** retrieves the completed result from Neon. If Process A restarts, the unexpired result remains durable and available in Neon.

---

## 6. Trusted Caller Adapter & Multi-Tenant Isolation

All verification operations require a `CallerContext`:

```python
from fayda_mcp import CallerContext

ctx = CallerContext(
    tenant_id="enterprise-org-1",
    principal_id="onboarding-service-worker",
    browser_binding="secure-cookie-hash-xyz",
    scopes=["verification:read", "verification:write"],
)
```

- **Tenant Isolation**: Requests and results belong strictly to `tenant_id`. Cross-tenant queries raise `AuthorizationError`.
- **Principal Protection**: Non-anonymous requests require matching `principal_id` or `verification:admin` scope.
- **Session Binding**: `browser_binding` binds the initiation session to the browser callback cookie, preventing session injection across browsers.

---

## 7. Supported Claim Capabilities & Tri-State Outputs

### Supported Predicates
- `identity_verified`: Confirms identity subject exists and is authenticated.
- `age_over_18`: Legacy alias verifying age is at least 18 years.
- `age_at_least_<N>`: Dynamic threshold check (e.g. `age_at_least_21`, `age_at_least_65`).
- `phone_verified`: Verifies citizen phone number was validated by provider.
- `email_verified`: Verifies citizen email was validated by provider.

### Tri-State Outputs
Predicate checks evaluate strictly to tri-state values:
- `True`: Claim is present, valid, and meets the criteria.
- `False`: Claim is present and valid, but fails the criteria (e.g. age < 18).
- `None` (`unavailable`): Claim was not supplied by provider, consent was denied, or the value is malformed.

```json
{
  "request_id": "vr_abc123",
  "status": "verified",
  "checks": {
    "identity_verified": true,
    "age_over_18": true,
    "phone_verified": null
  }
}
```

---

## 8. Date of Birth Calendar & Age Calculation

- **Anniversary Calculation**: Age is calculated using exact calendar anniversaries (`today.year - dob.year`), never by dividing days by 365 or 365.25.
- **February 29 Rule**: In non-leap years, citizens born on February 29 reach their anniversary on **March 1** by default (configurable to `february_28` via policy).
- **Timezone**: Age evaluation defaults to `Africa/Addis_Ababa` timezone unless overridden in policy.

---

## 9. Production Retention Cleanup

Retention cleanup purges expired requests and results past their retention window.

> **Operational Rule**: Retention cleanup must be scheduled outside the core request path (e.g. via cron, systemd timer, or scheduled worker) to avoid adding query latency to verification transactions:

```bash
# Run retention cleanup via CLI
fayda-mcp cleanup --database-url-env DATABASE_URL --env-file .env
```

Example crontab (running every hour):
```cron
0 * * * * fayda-mcp cleanup --database-url-env DATABASE_URL > /var/log/fayda_cleanup.log 2>&1
```

---

## 10. Privacy Filtering Across Tools, Prompts & Logs

- **Zero Demographic / Biometric Leaks**: Tools, LLM prompts, resources, and debug endpoints output **only** minimal boolean predicate flags.
- **Disallowed Fields**: Fields such as `biometrics`, `fingerprints`, `photo`, `national_id`, `fayda_number`, `access_token`, and `id_token` are permanently stripped and never logged.
- **Safe Audit Logging**: The `fayda_audit_events` table and audit logger strictly record metadata event types and request identifiers, with zero demographic or credential content.
