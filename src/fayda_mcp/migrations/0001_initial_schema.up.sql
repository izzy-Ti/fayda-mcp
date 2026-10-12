-- 0001_initial_schema.up.sql
-- Fayda MCP Durable Storage Schema (Version 0001)

-- 1. Migrations Tracking Table
CREATE TABLE IF NOT EXISTS fayda_schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    description VARCHAR(256) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Verification Requests Table
CREATE TABLE IF NOT EXISTS fayda_requests (
    request_id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(128) NOT NULL,
    application_user_ref VARCHAR(256),
    idempotency_key VARCHAR(128),
    request_fingerprint VARCHAR(128),
    purpose VARCHAR(256),
    checks JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_expires_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    policy_version VARCHAR(32) DEFAULT 'v1',
    auth_url TEXT,
    method VARCHAR(64),
    profile VARCHAR(64),
    key_reference VARCHAR(128),
    evidence_ref VARCHAR(256),
    times TEXT,
    reasons TEXT,
    credential_signature_valid BOOLEAN,
    verified_at TIMESTAMPTZ,
    CONSTRAINT uq_fayda_requests_idemp UNIQUE (tenant_id, principal_id, idempotency_key),
    CONSTRAINT uq_fayda_requests_tenant_req UNIQUE (tenant_id, principal_id, request_id)
);

-- 3. Verification Results Table
CREATE TABLE IF NOT EXISTS fayda_results (
    request_id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(128) NOT NULL,
    status VARCHAR(64) NOT NULL,
    checks JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_at TIMESTAMPTZ,
    result_expires_at TIMESTAMPTZ NOT NULL,
    evidence_ref VARCHAR(256),
    policy_version VARCHAR(32) DEFAULT 'v1',
    method VARCHAR(64),
    profile VARCHAR(64),
    key_reference VARCHAR(128),
    CONSTRAINT fk_fayda_results_requests FOREIGN KEY (tenant_id, principal_id, request_id)
        REFERENCES fayda_requests (tenant_id, principal_id, request_id)
        ON DELETE CASCADE
);

-- 4. Safe Audit Events Table
-- Strictly forbids demographic payloads, raw tokens, biometrics, or signing keys
CREATE TABLE IF NOT EXISTS fayda_audit_events (
    event_id VARCHAR(128) PRIMARY KEY,
    request_id VARCHAR(128),
    tenant_id VARCHAR(128) NOT NULL,
    principal_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    method VARCHAR(64),
    profile VARCHAR(64),
    key_reference VARCHAR(128),
    policy_version VARCHAR(32)
);

-- 5. Performance, Caller Isolation, and Expiry Indexes
CREATE INDEX IF NOT EXISTS idx_fayda_requests_caller ON fayda_requests (tenant_id, principal_id);
CREATE INDEX IF NOT EXISTS idx_fayda_requests_retention ON fayda_requests (retention_expires_at);
CREATE INDEX IF NOT EXISTS idx_fayda_results_caller ON fayda_results (tenant_id, principal_id);
CREATE INDEX IF NOT EXISTS idx_fayda_results_expiry ON fayda_results (result_expires_at);
CREATE INDEX IF NOT EXISTS idx_fayda_audit_timeline ON fayda_audit_events (tenant_id, principal_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_fayda_audit_request ON fayda_audit_events (request_id, occurred_at DESC);
