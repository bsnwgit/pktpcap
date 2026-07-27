-- pktPCAP initial schema (fresh rebuild — no upgrade path from the old
-- Flask app's sha256-hashed users or ad-hoc executescript schema; see the
-- rebuild plan's "force-reset at cutover" decision).

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    hashed_password TEXT,
    role            TEXT NOT NULL DEFAULT 'viewer',   -- admin | analyst | viewer
    is_active       INTEGER NOT NULL DEFAULT 1,
    is_default_admin INTEGER NOT NULL DEFAULT 0,        -- auto-logged-in when all auth methods are disabled
    auth_provider   TEXT NOT NULL DEFAULT 'local',      -- local | saml
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
);

-- Generic key/value store for runtime settings (JSON-encoded values),
-- mirrors the pattern used across the pkt* suite.
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    level       TEXT NOT NULL,
    level_no    INTEGER NOT NULL,
    logger      TEXT NOT NULL,
    message     TEXT NOT NULL,
    exc_info    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_logs_created ON app_logs(created_at);

-- Outbound suite integrations (pktPCAP acting as a client of sibling apps).
-- Named multi-instance per app_name, matching the current suite convention
-- (see pktwifi/pktipam migrations) rather than the old one-row-per-app_name
-- shape the original Flask app started with.
CREATE TABLE IF NOT EXISTS integrations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,   -- user-given label, e.g. "Main pktsnmp"
    app_name          TEXT NOT NULL,
    base_url          TEXT NOT NULL DEFAULT '',
    suite_token       TEXT NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1,
    health_status     TEXT NOT NULL DEFAULT 'unknown',
    last_health_check TEXT,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_integrations_app_name ON integrations(app_name);

-- Per-user external API keys for IP reputation/intelligence lookups
-- (AbuseIPDB, IPQualityScore, ipinfo.io, ipapi.is, MXToolbox). Keyed by
-- username rather than user id: suite-proxy (pktHub) requests share a
-- single pseudo user id of 0 across every hub-authenticated identity, so
-- id would not actually be per-user for that auth path.
CREATE TABLE IF NOT EXISTS user_api_keys (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL,
    provider       TEXT NOT NULL,
    api_key        TEXT NOT NULL DEFAULT '',
    enabled_fields TEXT DEFAULT NULL,           -- JSON array; NULL = not customized, all shown
    free_tier      INTEGER NOT NULL DEFAULT 0,   -- ipapi_is only — use its keyless free tier
    enabled        INTEGER NOT NULL DEFAULT 1,   -- show this provider's section in the IP Lookup modal at all
    updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (username, provider)
);
