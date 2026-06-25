-- migrations/003_create_security_chat_history.sql
-- ─────────────────────────────────────────────────
-- Stores all messages in the interactive security Q&A chat.
-- Messages are grouped by session_id for context continuity.

CREATE TABLE IF NOT EXISTS security_chat_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    device_id       TEXT,
    user_id         INTEGER,
    role            TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
    message         TEXT NOT NULL,
    token_count     INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_session_id
    ON security_chat_history(session_id);
