-- migrations/009_create_mfa_and_sessions.sql
-- ──────────────────────────────────────────────
-- Extends dashboard_users with MFA secrets, locks, and failed login counts.
-- Extends dashboard_sessions with MFA verification state.

-- 1. Add MFA and lock columns to dashboard_users
ALTER TABLE dashboard_users ADD COLUMN tenant_id TEXT;
ALTER TABLE dashboard_users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;
ALTER TABLE dashboard_users ADD COLUMN mfa_secret_encrypted TEXT;
ALTER TABLE dashboard_users ADD COLUMN mfa_backup_codes TEXT;
ALTER TABLE dashboard_users ADD COLUMN failed_login_count INTEGER DEFAULT 0;
ALTER TABLE dashboard_users ADD COLUMN locked_until TEXT;
ALTER TABLE dashboard_users ADD COLUMN last_ip TEXT;

-- 2. Rebuild dashboard_sessions to add tenant_id and mfa_verified
PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS dashboard_sessions_old;
ALTER TABLE dashboard_sessions RENAME TO dashboard_sessions_old;

CREATE TABLE dashboard_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    tenant_id      TEXT,
    session_token  TEXT NOT NULL UNIQUE,
    expires_at     TEXT NOT NULL,
    ip_address     TEXT,
    user_agent     TEXT,
    created_at     TEXT DEFAULT (datetime('now')),
    mfa_verified   INTEGER DEFAULT 0,
    is_active      INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id) ON DELETE CASCADE
);

-- Copy existing sessions over, defaulting mfa_verified to 0
INSERT INTO dashboard_sessions (
    id, user_id, session_token, expires_at, ip_address, user_agent, created_at, is_active, mfa_verified
)
SELECT
    id, user_id, session_token, expires_at, ip_address, user_agent, created_at, is_active, 0
FROM dashboard_sessions_old;

DROP TABLE IF EXISTS dashboard_sessions_old;

CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_token
    ON dashboard_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_user
    ON dashboard_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_tenant
    ON dashboard_sessions(tenant_id);

PRAGMA foreign_keys = ON;
