-- 008_repair_security_chat_history.sql
-- Rebuild security_chat_history so it always references dashboard_users.
-- This repairs older databases that still point at the legacy users table.

PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS security_chat_history_backup;

ALTER TABLE security_chat_history RENAME TO security_chat_history_backup;

CREATE TABLE security_chat_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    device_id       TEXT,
    user_id         INTEGER,
    role            TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
    message         TEXT NOT NULL,
    token_count     INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id) ON DELETE SET NULL
);

INSERT INTO security_chat_history (
    id, session_id, device_id, user_id, role, message, token_count, created_at
)
SELECT
    id, session_id, device_id, user_id, role, message, token_count, created_at
FROM security_chat_history_backup;

DROP TABLE security_chat_history_backup;

CREATE INDEX IF NOT EXISTS idx_chat_session_id
    ON security_chat_history(session_id);

PRAGMA foreign_keys = ON;
