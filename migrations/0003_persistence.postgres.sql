-- Migration 0003: Persist enforcement queue, breakglass sessions, audit log
-- Postgres-specific version (postgresql://)
-- Use with: python scripts/run_migrations.py (auto-detected)
--
-- Differences from SQLite version:
--   • AUTOINCREMENT → GENERATED ALWAYS AS IDENTITY
--   • No "CREATE INDEX IF NOT EXISTS" (not valid in Postgres)
--   • BOOLEAN stored as BOOLEAN (not INTEGER 0/1)
--   • All other logic identical

-- ── Pending approvals queue ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id  TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    context      TEXT NOT NULL,
    actor        TEXT NOT NULL,
    risk_score   INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL,
    decision     TEXT,
    decided_by   TEXT,
    decided_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_tenant  ON pending_approvals(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_approvals(status);
CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_approvals(created_at);

-- ── Breakglass sessions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS breakglass_sessions (
    breakglass_id       TEXT PRIMARY KEY,
    approved            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    actor              TEXT NOT NULL,
    reason             TEXT NOT NULL,
    pin_hash           TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    actions_overridden TEXT NOT NULL,
    status             TEXT NOT NULL,
    used               BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_bg_tenant   ON breakglass_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bg_status  ON breakglass_sessions(status);
CREATE INDEX IF NOT EXISTS idx_bg_expires ON breakglass_sessions(expires_at);

-- ── Immutable audit log (hash-chained) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    decision      TEXT NOT NULL,
    context       TEXT NOT NULL,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    breakglass_id TEXT,
    metadata      TEXT,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL,
    timestamp     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_act   ON audit_log(tenant_id, action);
