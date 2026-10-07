"""PostgreSQL / Neon durable result repository and audit logger."""

import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional
from fayda_mcp.schemas import VerificationResult

try:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
except ImportError:
    AsyncSession = None  # type: ignore
    async_sessionmaker = None  # type: ignore
    AsyncEngine = None  # type: ignore
    create_async_engine = None  # type: ignore
    text = None  # type: ignore


def _sql_text(statement: str) -> Any:
    if text is None:
        raise ImportError(
            "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
        )
    return text(statement)


class PostgresResultRepository:
    """PostgreSQL / Neon backed storage adapter using parameterized SQL.

    Implements the ResultRepository protocol with explicit caller namespaces,
    atomic race-safe finalization, idempotency indexing, and retention cleanup.
    Table creation and migrations are never executed automatically on import.
    """

    def __init__(
        self,
        session_factory: Any,
        engine: Optional[Any] = None,
        table_prefix: str = "fayda_",
    ) -> None:
        if AsyncSession is None or text is None:
            raise ImportError(
                "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
            )
        self.session_factory = session_factory
        self._engine = engine
        self._owned_engine = False
        self.table_prefix = table_prefix
        self._lock = asyncio.Lock()

        # Sanitized table names
        self.requests_table = f"{table_prefix}requests"
        self.results_table = f"{table_prefix}results"
        self.audit_table = f"{table_prefix}audit_events"

    @classmethod
    def from_url(
        cls,
        database_url: str,
        table_prefix: str = "fayda_",
        **engine_kwargs: Any,
    ) -> "PostgresResultRepository":
        """Create a PostgresResultRepository instance from a database connection URL."""
        if create_async_engine is None or async_sessionmaker is None:
            raise ImportError(
                "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
            )
        # Ensure async driver URL format
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        elif database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)

        engine = create_async_engine(database_url, **engine_kwargs)
        factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        repo = cls(session_factory=factory, engine=engine, table_prefix=table_prefix)
        repo._owned_engine = True
        return repo

    async def create_tables(self) -> None:
        """Create storage tables and indexes if they do not exist."""
        ddl_statements = [
            f"""
            CREATE TABLE IF NOT EXISTS {self.requests_table} (
                request_id VARCHAR(128) PRIMARY KEY,
                tenant_id VARCHAR(128) NOT NULL,
                principal_id VARCHAR(128) NOT NULL,
                application_user_ref VARCHAR(256),
                idempotency_key VARCHAR(256),
                request_fingerprint VARCHAR(128),
                purpose VARCHAR(128),
                checks TEXT NOT NULL,
                status VARCHAR(64) NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                session_expires_at DOUBLE PRECISION NOT NULL,
                retention_expires_at DOUBLE PRECISION NOT NULL,
                policy_version VARCHAR(32),
                auth_url TEXT,
                CONSTRAINT uq_{self.table_prefix}req_idemp UNIQUE (tenant_id, principal_id, idempotency_key)
            );
            """,
            f"""
            CREATE TABLE IF NOT EXISTS {self.results_table} (
                request_id VARCHAR(128) PRIMARY KEY,
                tenant_id VARCHAR(128) NOT NULL,
                principal_id VARCHAR(128) NOT NULL,
                status VARCHAR(64) NOT NULL,
                checks TEXT NOT NULL,
                verified_at VARCHAR(64),
                result_expires_at DOUBLE PRECISION NOT NULL,
                evidence_ref VARCHAR(256),
                policy_version VARCHAR(32)
            );
            """,
            f"""
            CREATE TABLE IF NOT EXISTS {self.audit_table} (
                event_id VARCHAR(128) PRIMARY KEY,
                request_id VARCHAR(128),
                tenant_id VARCHAR(128),
                principal_id VARCHAR(128),
                event_type VARCHAR(64) NOT NULL,
                occurred_at DOUBLE PRECISION NOT NULL,
                safe_metadata TEXT NOT NULL
            );
            """,
        ]

        async with self.session_factory() as session:
            async with session.begin():
                for stmt in ddl_statements:
                    await session.execute(_sql_text(stmt))

    async def save_request(self, request_id: str, data: Dict[str, Any], ttl_seconds: int = 900) -> None:
        """Persist or update verification request record using parameterized SQL."""
        now = time.time()
        session_expires_at = now + ttl_seconds
        retention_expires_at = now + ttl_seconds

        req_copy = dict(data)
        tenant_id = str(req_copy.get("tenant_id", "default"))
        principal_id = str(req_copy.get("principal_id", "anonymous"))
        app_user_ref = req_copy.get("application_user_ref")
        idempotency_key = req_copy.get("idempotency_key")
        purpose = req_copy.get("purpose")
        status = str(req_copy.get("status", "pending"))
        policy_version = req_copy.get("policy_version", "v1")
        auth_url = req_copy.get("authorization_url")
        checks_json = json.dumps(req_copy.get("checks", []))

        sql = f"""
        INSERT INTO {self.requests_table} (
            request_id, tenant_id, principal_id, application_user_ref,
            idempotency_key, request_fingerprint, purpose, checks,
            status, created_at, session_expires_at, retention_expires_at,
            policy_version, auth_url
        ) VALUES (
            :request_id, :tenant_id, :principal_id, :application_user_ref,
            :idempotency_key, :request_fingerprint, :purpose, :checks,
            :status, :created_at, :session_expires_at, :retention_expires_at,
            :policy_version, :auth_url
        )
        ON CONFLICT (request_id) DO UPDATE SET
            status = :status,
            checks = :checks,
            session_expires_at = :session_expires_at,
            retention_expires_at = :retention_expires_at
        """

        params = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "application_user_ref": app_user_ref,
            "idempotency_key": idempotency_key,
            "request_fingerprint": req_copy.get("request_fingerprint"),
            "purpose": purpose,
            "checks": checks_json,
            "status": status,
            "created_at": now,
            "session_expires_at": session_expires_at,
            "retention_expires_at": retention_expires_at,
            "policy_version": policy_version,
            "auth_url": auth_url,
        }

        async with self.session_factory() as session:
            async with session.begin():
                await session.execute(_sql_text(sql), params)

    async def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve verification request record by ID. Returns None if expired or not found."""
        sql = f"""
        SELECT request_id, tenant_id, principal_id, application_user_ref,
               idempotency_key, request_fingerprint, purpose, checks,
               status, created_at, session_expires_at, retention_expires_at,
               policy_version, auth_url
        FROM {self.requests_table}
        WHERE request_id = :request_id
        """

        async with self.session_factory() as session:
            result = await session.execute(_sql_text(sql), {"request_id": request_id})
            row = result.mappings().first()
            if not row:
                return None

            now = time.time()
            if now >= float(row["retention_expires_at"]):
                return None

            try:
                checks = json.loads(row["checks"])
            except Exception:
                checks = []

            return {
                "request_id": row["request_id"],
                "tenant_id": row["tenant_id"],
                "principal_id": row["principal_id"],
                "application_user_ref": row["application_user_ref"],
                "idempotency_key": row["idempotency_key"],
                "request_fingerprint": row["request_fingerprint"],
                "purpose": row["purpose"],
                "checks": checks,
                "status": row["status"],
                "created_at": row["created_at"],
                "session_expires_at": row["session_expires_at"],
                "retention_expires_at": row["retention_expires_at"],
                "policy_version": row["policy_version"],
                "authorization_url": row["auth_url"],
            }

    async def find_by_idempotency_key(
        self, tenant_id: str, principal_id: str, idempotency_key: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve existing request matching tenant, principal, and caller idempotency key."""
        sql = f"""
        SELECT request_id, tenant_id, principal_id, application_user_ref,
               idempotency_key, request_fingerprint, purpose, checks,
               status, created_at, session_expires_at, retention_expires_at,
               policy_version, auth_url
        FROM {self.requests_table}
        WHERE tenant_id = :tenant_id
          AND principal_id = :principal_id
          AND idempotency_key = :idempotency_key
        """

        params = {
            "tenant_id": str(tenant_id),
            "principal_id": str(principal_id),
            "idempotency_key": str(idempotency_key),
        }

        async with self.session_factory() as session:
            result = await session.execute(_sql_text(sql), params)
            row = result.mappings().first()
            if not row:
                return None

            now = time.time()
            if now >= float(row["retention_expires_at"]):
                return None

            try:
                checks = json.loads(row["checks"])
            except Exception:
                checks = []

            return {
                "request_id": row["request_id"],
                "tenant_id": row["tenant_id"],
                "principal_id": row["principal_id"],
                "application_user_ref": row["application_user_ref"],
                "idempotency_key": row["idempotency_key"],
                "request_fingerprint": row["request_fingerprint"],
                "purpose": row["purpose"],
                "checks": checks,
                "status": row["status"],
                "created_at": row["created_at"],
                "session_expires_at": row["session_expires_at"],
                "retention_expires_at": row["retention_expires_at"],
                "policy_version": row["policy_version"],
                "authorization_url": row["auth_url"],
            }

    async def update_status(self, request_id: str, status: str) -> None:
        """Update request status (pending, processing, cancelled, etc.)."""
        sql = f"""
        UPDATE {self.requests_table}
        SET status = :status
        WHERE request_id = :request_id
        """
        async with self.session_factory() as session:
            async with session.begin():
                await session.execute(_sql_text(sql), {"request_id": request_id, "status": status})

    async def finalize_result(
        self, request_id: str, result: VerificationResult, ttl_seconds: int = 900
    ) -> bool:
        """Atomically finalize verification outcome in a single transaction.

        Returns True if transitioning from non-terminal state to result.status.
        Returns False if the request does not exist or has already been finalized.
        """
        now = time.time()
        result_expires_at = now + ttl_seconds
        checks_json = json.dumps(result.checks)

        # 1. Atomic conditional update on requests table
        sql_update = f"""
        UPDATE {self.requests_table}
        SET status = :status
        WHERE request_id = :request_id
          AND status NOT IN ('verified', 'rejected', 'failed', 'cancelled')
        """

        # 2. Insert into results table
        sql_insert_result = f"""
        INSERT INTO {self.results_table} (
            request_id, tenant_id, principal_id, status, checks,
            verified_at, result_expires_at, evidence_ref, policy_version
        )
        SELECT
            r.request_id, r.tenant_id, r.principal_id, :status, :checks,
            :verified_at, :result_expires_at, :evidence_ref, :policy_version
        FROM {self.requests_table} r
        WHERE r.request_id = :request_id
        ON CONFLICT (request_id) DO UPDATE SET
            status = :status,
            checks = :checks,
            verified_at = :verified_at,
            result_expires_at = :result_expires_at
        """

        async with self._lock:
            async with self.session_factory() as session:
                async with session.begin():
                    res = await session.execute(
                        _sql_text(sql_update), {"request_id": request_id, "status": result.status}
                    )
                    if res.rowcount == 0:
                        return False

                    params_insert = {
                        "request_id": request_id,
                        "status": result.status,
                        "checks": checks_json,
                        "verified_at": result.verified_at,
                        "result_expires_at": result_expires_at,
                        "evidence_ref": None,
                        "policy_version": "v1",
                    }
                    await session.execute(_sql_text(sql_insert_result), params_insert)
                    return True

    async def save_result(self, request_id: str, result: VerificationResult, ttl_seconds: int = 900) -> None:
        """Store final evaluated verification result."""
        now = time.time()
        result_expires_at = now + ttl_seconds
        checks_json = json.dumps(result.checks)

        sql_update_req = f"""
        UPDATE {self.requests_table}
        SET status = :status
        WHERE request_id = :request_id
        """

        sql_upsert_res = f"""
        INSERT INTO {self.results_table} (
            request_id, tenant_id, principal_id, status, checks,
            verified_at, result_expires_at, evidence_ref, policy_version
        )
        SELECT
            r.request_id, r.tenant_id, r.principal_id, :status, :checks,
            :verified_at, :result_expires_at, :evidence_ref, :policy_version
        FROM {self.requests_table} r
        WHERE r.request_id = :request_id
        ON CONFLICT (request_id) DO UPDATE SET
            status = :status,
            checks = :checks,
            verified_at = :verified_at,
            result_expires_at = :result_expires_at
        """

        async with self.session_factory() as session:
            async with session.begin():
                await session.execute(
                    _sql_text(sql_update_req), {"request_id": request_id, "status": result.status}
                )
                params = {
                    "request_id": request_id,
                    "status": result.status,
                    "checks": checks_json,
                    "verified_at": result.verified_at,
                    "result_expires_at": result_expires_at,
                    "evidence_ref": None,
                    "policy_version": "v1",
                }
                await session.execute(_sql_text(sql_upsert_res), params)

    async def get_result(self, request_id: str) -> Optional[VerificationResult]:
        """Retrieve final evaluated verification result."""
        sql = f"""
        SELECT request_id, status, checks, verified_at, result_expires_at
        FROM {self.results_table}
        WHERE request_id = :request_id
        """

        async with self.session_factory() as session:
            res = await session.execute(_sql_text(sql), {"request_id": request_id})
            row = res.mappings().first()
            if not row:
                return None

            now = time.time()
            if now >= float(row["result_expires_at"]):
                return None

            try:
                checks = json.loads(row["checks"])
            except Exception:
                checks = {}

            return VerificationResult(
                request_id=row["request_id"],
                status=row["status"],
                checks=checks,
                verified_at=row["verified_at"],
            )

    async def cleanup(self) -> int:
        """Purge expired requests and results. Returns total count of deleted records."""
        now = time.time()
        sql_del_reqs = f"DELETE FROM {self.requests_table} WHERE retention_expires_at <= :now"
        sql_del_results = f"DELETE FROM {self.results_table} WHERE result_expires_at <= :now"

        async with self.session_factory() as session:
            async with session.begin():
                r1 = await session.execute(_sql_text(sql_del_reqs), {"now": now})
                r2 = await session.execute(_sql_text(sql_del_results), {"now": now})
                return (r1.rowcount or 0) + (r2.rowcount or 0)

    async def close(self) -> None:
        """Lifecycle close: dispose owned engine if created by from_url."""
        if self._owned_engine and self._engine is not None:
            await self._engine.dispose()


class PostgresAuditLogger:
    """PostgreSQL / Neon safe audit logger recording events into fayda_audit_events."""

    def __init__(self, session_factory: Any, table_prefix: str = "fayda_") -> None:
        if AsyncSession is None or text is None:
            raise ImportError(
                "Postgres extra is not installed. Install with: pip install 'fayda-mcp[postgres]'"
            )
        self.session_factory = session_factory
        self.audit_table = f"{table_prefix}audit_events"

    async def record_event(self, event_type: str, safe_metadata: Dict[str, Any]) -> None:
        """Append safe audit log record."""
        event_id = str(uuid.uuid4())
        occurred_at = time.time()
        request_id = safe_metadata.get("request_id")
        tenant_id = safe_metadata.get("tenant_id")
        principal_id = safe_metadata.get("principal_id")
        metadata_json = json.dumps(safe_metadata)

        sql = f"""
        INSERT INTO {self.audit_table} (
            event_id, request_id, tenant_id, principal_id, event_type, occurred_at, safe_metadata
        ) VALUES (
            :event_id, :request_id, :tenant_id, :principal_id, :event_type, :occurred_at, :safe_metadata
        )
        """

        params = {
            "event_id": event_id,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "safe_metadata": metadata_json,
        }

        async with self.session_factory() as session:
            async with session.begin():
                await session.execute(_sql_text(sql), params)

    async def get_events(self, request_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recorded audit events, optionally filtered by request_id."""
        if request_id is not None:
            sql = f"""
            SELECT event_id, request_id, tenant_id, principal_id, event_type, occurred_at, safe_metadata
            FROM {self.audit_table}
            WHERE request_id = :request_id
            ORDER BY occurred_at ASC
            """
            params: Dict[str, Any] = {"request_id": request_id}
        else:
            sql = f"""
            SELECT event_id, request_id, tenant_id, principal_id, event_type, occurred_at, safe_metadata
            FROM {self.audit_table}
            ORDER BY occurred_at ASC
            """
            params = {}

        async with self.session_factory() as session:
            result = await session.execute(_sql_text(sql), params)
            events = []
            for row in result.mappings().all():
                try:
                    metadata = json.loads(row["safe_metadata"])
                except Exception:
                    metadata = {}
                events.append(
                    {
                        "event_type": row["event_type"],
                        "metadata": metadata,
                        "timestamp": row["occurred_at"],
                    }
                )
            return events
