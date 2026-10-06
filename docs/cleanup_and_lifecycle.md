# Cleanup & Lifecycle Management

Managing background connections, cached tokens, and short-lived session states properly ensures high security and prevents memory or connection leaks.

---

## 1. Service Lifecycle Management

`FaydaVerificationService` manages an underlying HTTP client pool (`httpx.AsyncClient`) and JWKS cache. Always manage its lifecycle using one of the following patterns:

### Async Context Manager (Recommended for scripts & tests)

```python
async with FaydaVerificationService(config, sessions, results) as service:
    # Service connections are active
    ...
# Cleanly closed upon block exit (service.aclose() executed)
```

### Combined FastAPI/FastMCP Lifespan (Recommended for servers)

```python
from fayda_mcp.integrations.fastapi import create_combined_lifespan

lifespan = create_combined_lifespan(
    service=service,
    mcp_server=mcp_server,
)

app = FastAPI(lifespan=lifespan)
```
Using `create_combined_lifespan` guarantees:
1. `service` HTTP pools and caches start first.
2. `mcp_server` and host application start up cleanly.
3. Upon SIGTERM or shutdown, all components are gracefully closed in reverse order.

---

## 2. Session and Result Expiry (TTLs)

To prevent unbounded storage growth and eliminate stale cryptographic state, `fayda-mcp` enforces bounded TTLs on all stored data:

| Setting | Default | Purpose |
|---|---|---|
| `session_ttl_seconds` | 600s (10 min) | Lifetime of pending authorization state, nonce, and PKCE verifier |
| `result_ttl_seconds` | 900s (15 min) | Lifetime of completed minimal verification result |
| `jwks_cache_ttl_seconds` | 300s (5 min) | Cached Fayda public keys |

### Storage Adapter Behaviors

- **In-Memory Adapter (`MemorySessionStore`, `MemoryResultRepository`)**:
  Automatically prunes expired entries on access and lookup.
- **Redis Adapter**:
  Applies native Redis `EXPIRE` commands matching the configured TTL.
- **Postgres / Neon Adapter**:
  Stores `expires_at` ISO timestamps. An index on `expires_at` enables efficient scheduled cleanup jobs (e.g. `DELETE FROM fayda_sessions WHERE expires_at < NOW()`).
