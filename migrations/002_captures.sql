-- Metadata index for persisted capture files. The filesystem (storage_path)
-- stays the source of truth for bytes; this table exists so the UI can show
-- a capture the instant a feed finishes (or an upload lands) instead of
-- relying on a filesystem-listing race, and so a crash mid-write is visible
-- (status stays 'saving') instead of silently absent — the old Flask app
-- tracked captures purely via Path.iterdir(), with no DB record at all.
CREATE TABLE IF NOT EXISTS captures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    filename     TEXT NOT NULL UNIQUE,
    session_name TEXT,                              -- feed name that produced it, NULL for direct uploads
    source       TEXT NOT NULL DEFAULT 'unknown',    -- tshark | wireshark | upload
    size_bytes   INTEGER,
    status       TEXT NOT NULL DEFAULT 'saved',      -- saving | saved | failed | missing
    created_by   INTEGER,                            -- users.id, NULL for machine-originated (feed ingest)
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_captures_created_at ON captures(created_at);
