-- Evaluation results: Guardian decisions linked to raw monitor_events
-- Written AFTER evaluation completes — never in same transaction as raw ingest

CREATE TABLE IF NOT EXISTS evaluation_results (
    id              UUID        PRIMARY KEY,
    monitor_event_id UUID       NOT NULL REFERENCES monitor_events(id) ON DELETE CASCADE,
    tenant_id       TEXT        NOT NULL,
    decision        TEXT        NOT NULL,  -- allow | review | block
    score           NUMERIC     NULL,
    reasons         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    policy_version   TEXT        NULL,
    evaluator_name  TEXT        NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evaluation_results_monitor_event_id
    ON evaluation_results (monitor_event_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_tenant_id
    ON evaluation_results (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_decision
    ON evaluation_results (decision);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_created_at
    ON evaluation_results (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_reasons_gin
    ON evaluation_results USING GIN (reasons);
