-- 007_create_incidents.sql
-- Incidents, fraud cases, compliance reports, notifications

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_number TEXT    NOT NULL UNIQUE,
    title           TEXT    NOT NULL,
    description     TEXT,
    severity        TEXT    NOT NULL DEFAULT 'MEDIUM',
    status          TEXT    NOT NULL DEFAULT 'OPEN',
    device_id       TEXT,
    assigned_to     INTEGER,
    created_by      INTEGER,
    threat_type     TEXT,
    risk_score      INTEGER,
    notes           TEXT,
    resolved_at     TEXT,
    created_at      TEXT    DEFAULT (datetime('now')),
    updated_at      TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (assigned_to) REFERENCES dashboard_users(id),
    FOREIGN KEY (created_by)  REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS fraud_cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL UNIQUE,
    device_id   TEXT,
    fraud_type  TEXT NOT NULL,
    risk_level  TEXT NOT NULL DEFAULT 'MEDIUM',
    status      TEXT NOT NULL DEFAULT 'OPEN',
    description TEXT,
    assigned_to INTEGER,
    evidence    TEXT,
    resolution  TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    resolved_at TEXT,
    FOREIGN KEY (assigned_to) REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id     TEXT NOT NULL UNIQUE,
    report_type   TEXT NOT NULL,
    standard      TEXT NOT NULL DEFAULT 'RBI',
    period_start  TEXT NOT NULL,
    period_end    TEXT NOT NULL,
    generated_by  INTEGER,
    summary_data  TEXT,
    status        TEXT DEFAULT 'GENERATED',
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (generated_by) REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    title      TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    type       TEXT    DEFAULT 'INFO',
    is_read    INTEGER DEFAULT 0,
    created_at TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_fraud_status       ON fraud_cases(status);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
