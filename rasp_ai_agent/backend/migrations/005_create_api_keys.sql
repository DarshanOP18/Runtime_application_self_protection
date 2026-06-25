-- migrations/005_create_api_keys.sql
-- ────────────────────────────────────
-- API key store for authenticating Flutter clients and admin tools.
-- Only the SHA-256 hash of each key is stored — raw keys are never persisted.

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT NOT NULL UNIQUE,        -- SHA-256 of the actual key
    label       TEXT,
    is_active   INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now')),
    last_used   TEXT,
    rate_limit  INTEGER DEFAULT 100          -- requests per minute
);
