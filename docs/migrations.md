# Database Migrations and Durable Schema

This document outlines the durable PostgreSQL / Neon storage schema, versioned migrations system, CLI tooling, and operational upgrade/rollback strategies for the Fayda MCP library.

---

## Architecture Principles

1. **Explicit Invocations Only**: Importing `fayda_mcp`, `fayda_mcp.storage`, or `fayda_mcp.migrations` **never** creates tables, alters schemas, or connects to the database automatically.
2. **Separation of Privileges**: Production application workloads run under restricted database user accounts with only `SELECT`, `INSERT`, `UPDATE`, and `DELETE` permissions. Schema migrations run explicitly via administrative credentials (e.g., in a CI/CD pipeline or deployment initialization hook).
3. **Multi-Tenant Composite Keys**: To prevent cross-tenant references, the results table references requests using a composite foreign key `(tenant_id, principal_id, request_id)`.
4. **Strict Privacy Boundaries**: Demographics (names, DOB), raw contact values, OTPs, biometrics, access tokens, and cryptographic signing keys are **strictly forbidden** from result and audit tables.
5. **Auditing Reviewability**: Audit tables record safe metadata and timestamps to support retrospective operational review; they do not themselves establish legal compliance for a sector.

---

## Schema Reference

### 1. `fayda_requests`
Tracks initial verification intent, session TTL, and caller scoping.

| Column | Type | Constraints / Description |
|---|---|---|
| `request_id` | `VARCHAR(128)` | Primary Key |
| `tenant_id` | `VARCHAR(128)` | Caller tenant namespace |
| `principal_id` | `VARCHAR(128)` | Caller principal/agent namespace |
| `application_user_ref` | `VARCHAR(256)` | Optional host user reference |
| `idempotency_key` | `VARCHAR(128)` | Caller-provided idempotency key |
| `request_fingerprint` | `VARCHAR(128)` | Hash of verification parameters |
| `purpose` | `VARCHAR(256)` | Verification business purpose |
| `checks` | `JSONB` | Requested check list (e.g., `["identity_verified"]`) |
| `status` | `VARCHAR(64)` | Status: `pending`, `processing`, `verified`, `rejected`, `failed`, `cancelled` |
| `created_at` | `TIMESTAMPTZ` | Timestamp when request was initiated |
| `session_expires_at` | `TIMESTAMPTZ` | Expiry of interactive auth session |
| `retention_expires_at` | `TIMESTAMPTZ` | Hard retention expiry for cleanup |
| `policy_version` | `VARCHAR(32)` | Policy rule version (e.g., `v1`) |
| `auth_url` | `TEXT` | Ephemeral OIDC authorization URL (purged on completion) |

**Constraints & Indexes**:
- `UNIQUE (tenant_id, principal_id, idempotency_key)`: Prevents duplicate starts per caller.
- `UNIQUE (tenant_id, principal_id, request_id)`: Enables composite foreign key targeting.
- `CREATE INDEX idx_fayda_requests_caller ON fayda_requests (tenant_id, principal_id)`
- `CREATE INDEX idx_fayda_requests_retention ON fayda_requests (retention_expires_at)`

---

### 2. `fayda_results`
Stores the finalized verification outcome with boolean check predicates.

| Column | Type | Constraints / Description |
|---|---|---|
| `request_id` | `VARCHAR(128)` | Primary Key |
| `tenant_id` | `VARCHAR(128)` | Caller tenant namespace |
| `principal_id` | `VARCHAR(128)` | Caller principal/agent namespace |
| `status` | `VARCHAR(64)` | Final status (`verified`, `rejected`, `failed`, `cancelled`) |
| `checks` | `JSONB` | Check predicates: `{"identity_verified": true}` |
| `verified_at` | `TIMESTAMPTZ` | Timestamp when verification succeeded |
| `result_expires_at` | `TIMESTAMPTZ` | Cache retention TTL |
| `evidence_ref` | `VARCHAR(256)` | Opaque audit identifier |
| `policy_version` | `VARCHAR(32)` | Policy version used |

**Constraints & Indexes**:
- `FOREIGN KEY (tenant_id, principal_id, request_id) REFERENCES fayda_requests (tenant_id, principal_id, request_id) ON DELETE CASCADE`
- `CREATE INDEX idx_fayda_results_caller ON fayda_results (tenant_id, principal_id)`
- `CREATE INDEX idx_fayda_results_expiry ON fayda_results (result_expires_at)`

---

### 3. `fayda_audit_events`
Chronological record of state transitions and operational events.

| Column | Type | Constraints / Description |
|---|---|---|
| `event_id` | `VARCHAR(128)` | Primary Key (UUID) |
| `request_id` | `VARCHAR(128)` | Associated request ID |
| `tenant_id` | `VARCHAR(128)` | Caller tenant |
| `principal_id` | `VARCHAR(128)` | Caller principal |
| `event_type` | `VARCHAR(64)` | Event type: `started`, `completed`, `cancelled`, `purged` |
| `occurred_at` | `TIMESTAMPTZ` | Timestamp of event |
| `safe_metadata` | `JSONB` | Sanitized non-PII diagnostic metadata |

**Indexes**:
- `CREATE INDEX idx_fayda_audit_timeline ON fayda_audit_events (tenant_id, principal_id, occurred_at DESC)`
- `CREATE INDEX idx_fayda_audit_request ON fayda_audit_events (request_id, occurred_at DESC)`

---

## Migration CLI

The package exposes the `fayda-mcp` CLI command to manage database migrations.

### Applying Migrations (Upgrade)
Apply all pending versioned migrations:
```bash
# Using direct connection string
fayda-mcp migrate --database-url "postgresql+psycopg://user:pass@localhost:5432/fayda"

# Using environment variable
export DATABASE_MIGRATION_URL="postgresql+psycopg://user:pass@localhost:5432/fayda"
fayda-mcp migrate --database-url-env DATABASE_MIGRATION_URL

# With explicit .env file loading
fayda-mcp migrate --env-file .env --database-url-env DATABASE_MIGRATION_URL
```

### Checking Migration Status
Inspect currently applied and pending migrations:
```bash
fayda-mcp migrate --database-url-env DATABASE_MIGRATION_URL --status
```

### Rolling Back Migrations
Roll back the most recent migration step:
```bash
fayda-mcp migrate --database-url-env DATABASE_MIGRATION_URL --rollback
```

To roll back multiple steps:
```bash
fayda-mcp migrate --database-url-env DATABASE_MIGRATION_URL --rollback --steps 2
```

---

## Programmatic Usage

You can also run migrations directly from Python:

```python
import asyncio
from fayda_mcp.migrations import run_migrations, rollback_migrations, get_migration_status

async def setup():
    db_url = "postgresql+psycopg://admin:secret@neon.tech/fayda_db"
    
    # Check status
    status = await get_migration_status(db_url)
    print("Pending migrations:", status["pending"])
    
    # Run upgrade
    applied = await run_migrations(db_url)
    print("Applied migrations:", applied)

asyncio.run(setup())
```
