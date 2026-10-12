# Connection & Retention Controls (Task S4)

This document specifies the database connection topologies, security roles, and automated data retention controls for production deployments with **Neon (Serverless Postgres)** and compatible PostgreSQL environments.

---

## 1. Connection Architecture: Pooled Runtime vs Direct Migrations

Neon architectures provide two distinct connection modes:

```
+-------------------------------------------------------------------------------+
|                             PostgreSQL / Neon Topologies                      |
+-------------------------------------------------------------------------------+
|                                                                               |
|  [Fayda MCP Runtime Service]                         [CLI / Migration Runner] |
|              |                                                  |             |
|              | (sslmode=require)                                | (sslmode=   |
|              v                                                  v   require)  |
|     PgBouncer Connection Pooler                    Direct Neon Compute Node   |
|   (*-pooler.neon.tech, port 5432/6543)                 (*.neon.tech, port 5432)|
|              |                                                  |             |
|              | (Transaction Mode)                               | (Session/DDL|
|              v                                                  v   Support)  |
|  +-------------------------------------------------------------------------+  |
|  |                            Neon Postgres DB                             |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

### 1.1 Runtime Connections (`DATABASE_URL`)
- **Target**: Neon connection pooler hostname (e.g. `ep-cool-subdomain-pooler.us-east-2.aws.neon.tech`).
- **TLS Enforcement**: `sslmode=require` is enforced automatically by `PostgresResultRepository.from_url` for any remote endpoint if not explicitly provided.
- **Small Process Pool**: Because serverless container environments scale horizontally and PgBouncer operates in transaction pooling mode, `PostgresResultRepository` configures lean pool defaults:
  ```python
  pool_size = 5           # Bounded persistent connections per worker process
  max_overflow = 10       # Bounded surge connections
  pool_recycle = 300      # 5-minute recycle to avoid stale TCP connections
  pool_pre_ping = True    # Pre-ping health check before checkout
  ```

### 1.2 Migration Connections (`DATABASE_MIGRATION_URL`)
- **Target**: Direct Neon compute endpoint (without `-pooler`).
- **Why**: PgBouncer in transaction pooling mode disallows session-level locking and DDL operations required for reliable schema migrations.
- **CLI & Runner**: `fayda-mcp migrate` automatically prioritizes `DATABASE_MIGRATION_URL`, falling back to `DATABASE_URL` if direct URL is not configured.

---

## 2. Separate Database Roles

To maintain least privilege and prevent SQL injection or application bugs from altering database schemas, separate the migration role from the runtime application role:

### 2.1 Migrator Role (`fayda_migrator`)
Used exclusively by CI/CD pipelines or administrators executing `fayda-mcp migrate`:

```sql
-- Create migration user
CREATE ROLE fayda_migrator WITH LOGIN PASSWORD 'secure_migrator_password';
GRANT CONNECT ON DATABASE neondb TO fayda_migrator;
GRANT CREATE, USAGE ON SCHEMA public TO fayda_migrator;
```

### 2.2 Runtime Application Role (`fayda_app`)
Used by the runtime MCP server (`DATABASE_URL`):

```sql
-- Create runtime user with no DDL privileges
CREATE ROLE fayda_app WITH LOGIN PASSWORD 'secure_app_password';
GRANT CONNECT ON DATABASE neondb TO fayda_app;
GRANT USAGE ON SCHEMA public TO fayda_app;

-- Grant DML-only permissions on application tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fayda_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fayda_app;

-- Strictly revoke DDL permissions
REVOKE CREATE ON SCHEMA public FROM fayda_app;
```

---

## 3. Retention Controls & Cleanup Lifecycle

### 3.1 Read-Time Expiry Denial
Expired results are denied immediately on read **even before background cleanup executes**:
- Both `MemoryResultRepository` and `PostgresResultRepository` evaluate `result_expires_at` during `get_result()`.
- If `current_timestamp >= result_expires_at`, `get_result()` returns `None`.
- `FaydaVerificationService.get_verification_result()` immediately raises `VerificationNotFoundError(f"Verification result for '{request_id}' has expired")`.
- This eliminates any race window where stale identity verification data could be read after its retention policy has expired.

### 3.2 Scheduled Retention Cleanup

#### In-Process Background Task
For long-running FastAPI/FastMCP server instances, run the background cleanup task via `RetentionCleanupManager`:

```python
from fayda_mcp.storage.retention import RetentionCleanupManager

manager = RetentionCleanupManager(repository)
task = manager.start_periodic(interval_seconds=300.0)  # Every 5 minutes

# On graceful server shutdown:
await manager.stop()
```

#### External Cron / Scheduled CLI Job
For containerized or serverless deployments, trigger periodic cleanup via Kubernetes CronJob or systemd timer:

```bash
# Execute single-pass retention cleanup using environment variables
fayda-mcp cleanup --env-file /etc/fayda/.env

# Or explicitly pass the database URL
fayda-mcp cleanup --database-url "$DATABASE_URL"
```

The cleanup pass purges:
1. `fayda_requests` where `retention_expires_at <= NOW()`
2. `fayda_results` where `result_expires_at <= NOW()`
