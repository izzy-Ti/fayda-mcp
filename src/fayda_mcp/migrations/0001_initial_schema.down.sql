-- 0001_initial_schema.down.sql
-- Rollback Fayda MCP Durable Storage Schema (Version 0001)

-- 1. Drop Indexes
DROP INDEX IF EXISTS idx_fayda_audit_request;
DROP INDEX IF EXISTS idx_fayda_audit_timeline;
DROP INDEX IF EXISTS idx_fayda_results_expiry;
DROP INDEX IF EXISTS idx_fayda_results_caller;
DROP INDEX IF EXISTS idx_fayda_requests_retention;
DROP INDEX IF EXISTS idx_fayda_requests_caller;

-- 2. Drop Tables in reverse dependency order
DROP TABLE IF EXISTS fayda_audit_events;
DROP TABLE IF EXISTS fayda_results;
DROP TABLE IF EXISTS fayda_requests;
DELETE FROM fayda_schema_migrations WHERE version = '0001';
