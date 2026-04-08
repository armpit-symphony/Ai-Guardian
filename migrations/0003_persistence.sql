-- Migration 0003: Persist enforcement queue, breakglass sessions, audit log
-- Applied automatically by scripts/run_migrations.py on every startup.
--
-- What this enables:
--   • Approvals survive service restart  (pending → approved/denied path durable)
--   • Breakglass sessions survive restart  (one-time/revoked/expired state durable)
--   • Audit log entries survive restart  (hash chain unbroken across restarts)
--
-- PostgreSQL note: IF NOT EXISTS is not valid Postgres syntax for CREATE INDEX
-- so this file is SQLite-primary. Run with:
--   python scripts/run_migrations.py

-- ── Pending approvals queue ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id  TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    context      TEXT NOT NULL,   -- JSON
    actor        TEXT NOT NULL,
    risk_score   INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL,   -- pending | approved | denied | expired
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
    approved            INTEGER NOT NULL DEFAULT 1,   -- SQLite BOOL (0/1)
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    actor               TEXT NOT NULL,
    reason              TEXT NOT NULL,
    pin_hash            TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    actions_overridden  TEXT NOT NULL,   -- JSON list
    status              TEXT NOT NULL,   -- active | used | expired | revoked
    used                INTEGER NOT NULL DEFAULT 0   -- one-time use flag (0/1)
);

CREATE INDEX IF NOT EXISTS idx_bg_tenant   ON breakglass_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bg_status   ON breakglass_sessions(status);
CREATE INDEX IF NOT EXISTS idx_bg_expires ON breakglass_sessions(expires_at);

-- ── Immutable audit log (hash-chained) ───────────────────────────────────
-- prev_hash + hash enable tamper detection via /audit/verify.
-- Entries are append-only — no UPDATE or DELETE allowed.
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    decision      TEXT NOT NULL,
    context       TEXT NOT NULL,   -- JSON
    risk_score    INTEGER NOT NULL DEFAULT 0,
    breakglass_id TEXT,
    metadata      TEXT,             -- JSON (extra fields)
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL,
    timestamp     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_act   ON audit_log(tenant_id, action);
