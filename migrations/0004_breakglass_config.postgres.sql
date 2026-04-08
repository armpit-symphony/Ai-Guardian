-- Migration 0004: Mutable breakglass PIN hash (Postgres)
-- Adds a breakglass_config table for runtime-configurable settings.
-- Note: uses ON CONFLICT DO NOTHING instead of SQLite's INSERT OR IGNORE

CREATE TABLE IF NOT EXISTS breakglass_config (
    config_key  TEXT PRIMARY KEY,
    config_val  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT
);

-- Default PIN hash: SHA256('ai-guardian-breakglass-2026') = 7ea342c6dd9977fe30802c45f2b5f12f455cfc58ef76e2d1ff2c0fafb91c3385
INSERT INTO breakglass_config (config_key, config_val, updated_at, updated_by)
VALUES (
    'pin_hash',
    '7ea342c6dd9977fe30802c45f2b5f12f455cfc58ef76e2d1ff2c0fafb91c3385',
    '2026-04-08T00:00:00+00:00',
    NULL
) ON CONFLICT (config_key) DO NOTHING;
