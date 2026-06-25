-- migrations/004_create_risk_assessments.sql
-- ────────────────────────────────────────────
-- Stores structured risk assessment snapshots linked to threat_history.
-- Each row captures the threat flags, score breakdown, and computed level
-- at the moment of assessment.

CREATE TABLE IF NOT EXISTS risk_assessments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL,
    threat_id       INTEGER,
    risk_score      INTEGER NOT NULL,
    risk_level      TEXT NOT NULL,
    threat_flags    TEXT NOT NULL,           -- JSON array of active threats
    score_breakdown TEXT NOT NULL,           -- JSON object: {"root":50, "frida":80}
    assessed_at     TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (threat_id) REFERENCES threat_history(id) ON DELETE CASCADE
);
