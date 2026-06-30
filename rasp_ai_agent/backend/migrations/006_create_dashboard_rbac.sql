-- 006_create_dashboard_rbac.sql
-- Dashboard authentication and RBAC (separate from Flutter app)

CREATE TABLE IF NOT EXISTS dashboard_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    full_name     TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'READ_ONLY_AUDITOR',
    organization  TEXT    DEFAULT 'Default',
    is_active     INTEGER DEFAULT 1,
    last_login    TEXT,
    login_count   INTEGER DEFAULT 0,
    created_at    TEXT    DEFAULT (datetime('now')),
    created_by    INTEGER,
    FOREIGN KEY (created_by) REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS dashboard_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    session_token  TEXT    NOT NULL UNIQUE,
    expires_at     TEXT    NOT NULL,
    ip_address     TEXT,
    user_agent     TEXT,
    created_at     TEXT    DEFAULT (datetime('now')),
    is_active      INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id)
);

CREATE TABLE IF NOT EXISTS dashboard_audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER,
    username     TEXT,
    role         TEXT,
    action       TEXT NOT NULL,
    module       TEXT,
    resource_id  TEXT,
    ip_address   TEXT,
    details      TEXT,
    performed_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id)
);

CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token
    ON dashboard_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_user
    ON dashboard_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_dash_audit_user
    ON dashboard_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_dash_audit_action
    ON dashboard_audit_logs(action);

-- Seed default Super Admin
-- Password: Admin@Shield2024
-- Hash generated with: passlib.hash.bcrypt.hash("Admin@Shield2024")
INSERT OR IGNORE INTO dashboard_users
    (username, email, password_hash, full_name, role, organization)
VALUES (
    'superadmin',
    'superadmin@shield.local',
    '$2b$12$UPPSz12ORN423/E2CC35H.r6RZV5tiCxLfsdzuJJ/73XClIMjOJjy',
    'Super Administrator',
    'SUPER_ADMIN',
    'Shield Security'
);
