-- migrations/002_create_device_security_profile.sql
-- ──────────────────────────────────────────────────
-- Maintains a per-device security profile that tracks cumulative threat
-- statistics, the highest risk level ever recorded, and whether the device
-- has been blocked.

CREATE TABLE IF NOT EXISTS device_security_profile (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id               TEXT NOT NULL UNIQUE,
    user_id                 INTEGER,
    device_model            TEXT,
    os_version              TEXT,
    app_version             TEXT,
    first_seen_at           TEXT DEFAULT (datetime('now')),
    last_seen_at            TEXT DEFAULT (datetime('now')),
    total_threat_events     INTEGER DEFAULT 0,
    highest_risk_ever       TEXT DEFAULT 'LOW',
    is_blocked              INTEGER DEFAULT 0,
    block_reason            TEXT,
    trusted                 INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_device_profile_device_id
    ON device_security_profile(device_id);
