-- migrations/001_create_threat_history.sql
-- ─────────────────────────────────────────
-- Stores every threat detection event received from the Flutter RASP SDK.
-- Each row captures individual threat flags, the computed risk score/level,
-- LLM-generated explanation and recommendations, and the raw JSON payload.

CREATE TABLE IF NOT EXISTS threat_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT NOT NULL,
    user_id             INTEGER,              -- nullable FK to users.id
    root_detected       INTEGER DEFAULT 0,
    frida_detected      INTEGER DEFAULT 0,
    debugger_detected   INTEGER DEFAULT 0,
    emulator_detected   INTEGER DEFAULT 0,
    tamper_detected     INTEGER DEFAULT 0,
    vpn_detected        INTEGER DEFAULT 0,
    proxy_detected      INTEGER DEFAULT 0,
    overlay_detected    INTEGER DEFAULT 0,
    accessibility_abuse INTEGER DEFAULT 0,
    hook_detected       INTEGER DEFAULT 0,
    location_spoof      INTEGER DEFAULT 0,
    time_spoof          INTEGER DEFAULT 0,
    malware_detected    INTEGER DEFAULT 0,
    screenshot_detected INTEGER DEFAULT 0,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    risk_level          TEXT NOT NULL DEFAULT 'LOW',
    threat_summary      TEXT,
    llm_explanation     TEXT,
    llm_recommendation  TEXT,
    raw_payload         TEXT,                 -- full JSON from Flutter
    created_at          TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_history_device_id
    ON threat_history(device_id);
CREATE INDEX IF NOT EXISTS idx_threat_history_created_at
    ON threat_history(created_at);
CREATE INDEX IF NOT EXISTS idx_threat_history_risk_level
    ON threat_history(risk_level);
