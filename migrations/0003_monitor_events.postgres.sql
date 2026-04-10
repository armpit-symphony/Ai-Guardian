-- Migration 0003: monitor_events (PostgreSQL)
-- For PostgreSQL deployments (AI_GUARDIAN_DATABASE_URL)
-- Raw ingest log, written before evaluation — forensic ground truth.

CREATE TABLE IF NOT EXISTS monitor_events (
    id             UUID        PRIMARY KEY,
    tenant_id      TEXT        NOT NULL,
    agent_id       TEXT        NOT NULL,
    action         TEXT        NOT NULL,
    source_url     TEXT,
    context        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id     UUID        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_monitor_events_tenant_id   ON monitor_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_monitor_events_agent_id      ON monitor_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_monitor_events_received_at   ON monitor_events (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_events_request_id    ON monitor_events (request_id);
CREATE INDEX IF NOT EXISTS idx_monitor_events_context_gin  ON monitor_events USING GIN (context);
CREATE INDEX IF NOT EXISTS idx_monitor_events_metadata_gin ON monitor_events USING GIN (metadata);
