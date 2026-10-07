# Redis Session Adapter & Eviction Controls (Task S6)

This document specifies the Redis connection management, URL parsing rules, session key hashing, data privacy boundaries, and cache eviction / persistence behaviors for production deployments.

---

## 1. Connection Architecture & Strict URL Parsing

`RedisSessionStore` connects to Redis clusters or standalone instances using standard Redis connection URLs or documented `redis-cli` connection flags.

### 1.1 Supported URL Schemes
- **Unencrypted**: `redis://[[username]:[password]@]host[:port][/database]`
- **TLS Encrypted (Recommended for Production)**: `rediss://[[username]:[password]@]host[:port][/database]`

### 1.2 Documented CLI String Support
`RedisSessionStore.from_url` accepts:
1. **Bare URLs**: `redis://localhost:6379/0` or `rediss://user:secret@redis.prod:6380/1`
2. **Quoted URLs**: `'rediss://user:p%40ss@redis.prod:6380/1'`
3. **CLI Connection Strings**: `redis-cli -u "rediss://host:6379/0"` or `redis-cli --uri "rediss://host:6379/0"`

### 1.3 Strict Security & Shell Injection Protection
- **No Subprocess/Shell Execution**: Input is parsed purely in-memory using `shlex.split`. It is never executed in a shell.
- **Unsupported Flag Rejection**: Any flags other than `-u` or `--uri` (such as `-a`, `-p`, `--cluster`) are strictly rejected with `ValueError`.
- **Extra Command Rejection**: Trailing text or commands (e.g. `redis://host:6379 FLUSHALL` or `redis-cli -u redis://host INFO`) are strictly rejected.
- **Credential Protection**: Passwords with URL-encoded special characters (e.g. `%40`, `%3A`) survive parsing intact. Password credentials are automatically redacted in logs and error messages.

---

## 2. Session Key Architecture & Hashing

```
+--------------------------------------------------------------------------+
|                        OIDC Authorization Callback State                 |
|                                                                          |
|   state = "x8F2k... random high-entropy token ..."                       |
|                               |                                          |
|                               v                                          |
|                       SHA-256 Hashing                                    |
|                               |                                          |
|                               v                                          |
|   Redis Key: fayda:session:b5d2...64-char-hex...                         |
+--------------------------------------------------------------------------+
```

### 2.1 Namespaced State Hashing
- Every session key uses the dedicated namespace prefix: `fayda:session:`.
- The random `state` parameter is hashed with SHA-256: `fayda:session:<sha256(state)>`.
- **Benefits**:
  - Eliminates predictable or enumerable keys in Redis.
  - Prevents query parameter characters or oversized tokens from creating malformed keys.
  - Protects the raw authorization token from appearing in Redis `MONITOR` or keyspace notifications.

---

## 3. Session Value Privacy Boundary

Sessions in Redis are strictly transient cryptographic contexts. Redis stores:

| Field | Purpose |
|---|---|
| `request_id` | Opaque verification request reference |
| `tenant_id` | Multi-tenant namespace identifier |
| `principal_id` | Caller agent / service principal ID |
| `application_user_ref` | Opaque tenant user reference |
| `nonce` | OIDC cryptographic nonce |
| `code_verifier` | RFC 7636 PKCE code verifier |
| `purpose` | Business justification string |
| `checks` | Requested verification check names |
| `expires_at` | Session expiration ISO timestamp |
| `browser_binding` | Optional caller browser binding fingerprint |

> [!IMPORTANT]
> **Strict Privacy Invariant**: No demographic data (name, birthdate, gender, photo, national ID number) or raw OIDC tokens are ever stored in Redis.

---

## 4. Eviction & Persistence Behavior

### 4.1 Eviction Policy Configuration
In high-throughput environments where Redis memory limits (`maxmemory`) are approached:
- **Recommended**: `maxmemory-policy volatile-lru` or `maxmemory-policy noeviction`.
- **Discouraged**: `allkeys-lru` or `allkeys-random`.

> [!WARNING]
> Do not use `allkeys-lru`. If Redis evicts keys with active TTLs, in-flight user verifications waiting for user interaction on the Fayda identity portal could have their session data discarded before completion, resulting in false `InvalidStateError` failures.

### 4.2 Persistence Recommendation
- **RDB (Snapshotting)**: Keep standard periodic snapshots (`save 300 10`) for disaster recovery.
- **AOF (Append-Only File)**: Enable AOF with `appendfsync everysec` for high availability across container restarts.
- **TTL Bounding**: Every session is written with a strict TTL (default `session_ttl_seconds = 600`). Even without manual deletion, stale or abandoned sessions are automatically reclaimed by Redis.
