"""
Fix broken foreign key: security_chat_history.user_id references 'users'
but the actual table is 'dashboard_users'. Recreate with correct FK.
"""
import sqlite3

conn = sqlite3.connect('./data/rbac_security.db')
conn.execute("PRAGMA foreign_keys = OFF")

conn.executescript("""
-- Rename old table
ALTER TABLE security_chat_history RENAME TO security_chat_history_old;

-- Create new table with correct FK
CREATE TABLE security_chat_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    device_id   TEXT,
    user_id     INTEGER,
    role        TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
    message     TEXT NOT NULL,
    token_count INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES dashboard_users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_session_id ON security_chat_history(session_id);

-- Copy existing data
INSERT INTO security_chat_history
    SELECT id, session_id, device_id, user_id, role, message, token_count, created_at
    FROM security_chat_history_old;

-- Drop old table
DROP TABLE security_chat_history_old;
""")

conn.execute("PRAGMA foreign_keys = ON")
conn.commit()
conn.close()
print("Done! security_chat_history table fixed.")
