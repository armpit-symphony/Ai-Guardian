-- Normalized findings: unified schema for all product sources
-- Written AFTER monitor_events + evaluation_results are committed

CREATE TABLE IF NOT EXISTS findings (
    id                   UUID        PRIMARY KEY,
    tenant_id            TEXT        NOT NULL,
    monitor_event_id     UUID        NOT NULL REFERENCES monitor_events(id) ON DELETE CASCADE,
    evaluation_result_id UUID        NULL REFERENCES evaluation_results(id) ON DELETE SET NULL,
    source               TEXT        NOT NULL,
    source_finding_id    TEXT        NULL,
    type                 TEXT        NOT NULL,
    severity             TEXT        NOT NULL,
    confidence           NUMERIC     NULL,
    title                TEXT        NOT NULL,
    description          TEXT        NULL,
    service              TEXT        NULL,
    resource             TEXT        NULL,
    evidence             JSONB       NOT NULL DEFAULT '[]'::jsonb,
    context              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    raw_payload          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_id
    ON findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_monitor_event_id
    ON findings (monitor_event_id);
CREATE INDEX IF NOT EXISTS idx_findings_evaluation_result_id
    ON findings (evaluation_result_id);
CREATE INDEX IF NOT EXISTS idx_findings_source
    ON findings (source);
CREATE INDEX IF NOT EXISTS idx_findings_type
    ON findings (type);
CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_created_at
    ON findings (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_evidence_gin
    ON findings USING GIN (evidence);
CREATE INDEX IF NOT EXISTS idx_findings_context_gin
    ON findings USING GIN (context);
CREATE INDEX IF NOT EXISTS idx_findings_raw_payload_gin
    ON findings USING GIN (raw_payload);
