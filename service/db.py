#!/usr/bin/env python3
"""
db.py — SQLite database layer for pktPCAP.
Bootstrap: config.json holds only {"db_type":"sqlite","db_path":"pktpcap.db"}.
All app settings and users live in the SQLite database.
PCAP capture files are stored on disk at the path from the storage_path setting.
"""

import json, sqlite3, threading, hashlib, secrets, datetime
from pathlib import Path

BASE = Path(__file__).parent
CONFIG_FILE = BASE / "config.json"

# ── Default settings (used as fallback if key not in DB) ─────────────────────

DEFAULT_SETTINGS = {
    "port": 8765,
    "app_name": "pktPCAP",
    "provider": "anthropic",
    "anthropic_key": "",
    "anthropic_model": "claude-opus-4-8",
    "openai_key": "",
    "openai_model": "gpt-4o",
    "ssl_enabled": False,
    "ssl_cert": "",
    "ssl_key": "",
    # Storage
    "storage_path": "",
    "max_upload_mb": 500,
    "storage_quota_gb": 50,
    "retention_days": 90,
    "auto_purge": False,
    # Backup
    "auto_backup": False,
    "backup_interval_hours": 24,
    "backup_rotation": 7,
    "backup_path": "",
    "backup_include_captures": False,
    # Auth
    "local_auth_enabled": True,
    "session_timeout_minutes": 480,
    "okta_saml_enabled": False,
    "okta_metadata_xml": "",
    "okta_entity_id": "",
    "okta_sso_url": "",
    "okta_cert": "",
    # Notifications
    "notify_slack_enabled": False,
    "notify_slack_webhook_url": "",
    "notify_slack_channel": "",
    "notify_email_enabled": False,
    "notify_email_smtp_host": "",
    "notify_email_smtp_port": 587,
    "notify_email_smtp_tls": True,
    "notify_email_username": "",
    "notify_email_password": "",
    "notify_email_from": "",
    "notify_email_default_to": "",
    "notify_pagerduty_enabled": False,
    "notify_pagerduty_integration_key": "",
    "notify_webhook_enabled": False,
    "notify_webhook_url": "",
    "notify_webhook_method": "POST",
    "notify_webhook_payload_template": "",
    "notify_tracecat_enabled": False,
    "notify_tracecat_webhook_url": "",
    "notify_tracecat_api_token": "",
    # Integrations
    "lucid_api_token": "",
    "pfx_mode": False,
    "pfx_path": "",
    "pfx_passphrase": "",
    "pem_cert_path": "",
    "pem_key_path": "",
}

# ── Bootstrap config ──────────────────────────────────────────────────────────

DEFAULT_DB_CONFIG = {"db_type": "sqlite", "db_path": "pktpcap.db"}


def load_db_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            return {
                "db_type": data.get("db_type", "sqlite"),
                "db_path": data.get("db_path", "pktpcap.db"),
            }
        except Exception:
            pass
    return dict(DEFAULT_DB_CONFIG)


def save_db_config(db_type: str, db_path: str):
    CONFIG_FILE.write_text(json.dumps({"db_type": db_type, "db_path": db_path}, indent=2))


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"


def check_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False


# ── Database class ────────────────────────────────────────────────────────────

class Database:
    """Thread-safe SQLite database for pktPCAP settings and users."""

    def __init__(self, db_path: str):
        if not Path(db_path).is_absolute():
            db_path = str(BASE / db_path)
        self.db_path = db_path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._init_schema()

    # ── Connection ────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_schema(self):
        with self._write_lock:
            c = self._conn()
            c.executescript("""
                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT    NOT NULL UNIQUE,
                    email         TEXT    DEFAULT '',
                    role          TEXT    NOT NULL DEFAULT 'viewer',
                    status        TEXT    NOT NULL DEFAULT 'active',
                    password_hash TEXT    NOT NULL,
                    last_login    TEXT,
                    created_at    TEXT    NOT NULL
                );
            """)
            c.commit()

    # ── Settings ──────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default=None):
        row = self._conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except Exception:
            return row[0]

    def set_setting(self, key: str, value):
        with self._write_lock:
            self._conn().execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, json.dumps(value)),
            )
            self._conn().commit()

    def get_all_settings(self) -> dict:
        rows = self._conn().execute("SELECT key, value FROM settings").fetchall()
        result = dict(DEFAULT_SETTINGS)
        for row in rows:
            try:
                result[row[0]] = json.loads(row[1])
            except Exception:
                result[row[0]] = row[1]
        return result

    def set_many_settings(self, d: dict):
        with self._write_lock:
            c = self._conn()
            for k, v in d.items():
                c.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (k, json.dumps(v)),
                )
            c.commit()

    # ── Users ─────────────────────────────────────────────────────────────────

    def get_users(self) -> list:
        rows = self._conn().execute(
            "SELECT id, username, email, role, status, last_login, created_at FROM users"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_user(self, uid: int):
        row = self._conn().execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
        return dict(row) if row else None

    def get_user_by_username(self, username: str):
        row = self._conn().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def get_user_by_email(self, email: str):
        if not email:
            return None
        row = self._conn().execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)
        ).fetchone()
        return dict(row) if row else None

    def create_user(self, username: str, email: str, role: str, password_hash: str) -> int:
        now = datetime.datetime.utcnow().isoformat()
        with self._write_lock:
            cur = self._conn().execute(
                "INSERT INTO users (username, email, role, status, password_hash, created_at) "
                "VALUES (?, ?, ?, 'active', ?, ?)",
                (username, email or "", role, password_hash, now),
            )
            self._conn().commit()
            return cur.lastrowid

    def update_user(self, uid: int, fields: dict):
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [uid]
        with self._write_lock:
            self._conn().execute(f"UPDATE users SET {sets} WHERE id = ?", vals)
            self._conn().commit()

    def delete_user(self, uid: int):
        with self._write_lock:
            self._conn().execute("DELETE FROM users WHERE id = ?", (uid,))
            self._conn().commit()

    def count_active_admins(self) -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'"
        ).fetchone()
        return row[0]

    def export_all(self) -> dict:
        """Export full data including password hashes (for migration)."""
        rows = self._conn().execute("SELECT * FROM users").fetchall()
        return {
            "settings": self.get_all_settings(),
            "users": [dict(r) for r in rows],
        }

    def import_all(self, data: dict):
        """Import exported data (used during DB migration)."""
        self.set_many_settings(data.get("settings", {}))
        with self._write_lock:
            c = self._conn()
            for u in data.get("users", []):
                try:
                    c.execute(
                        "INSERT OR IGNORE INTO users "
                        "(username, email, role, status, password_hash, last_login, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            u["username"], u.get("email", ""), u.get("role", "viewer"),
                            u.get("status", "active"), u.get("password_hash", ""),
                            u.get("last_login"), u.get("created_at", datetime.datetime.utcnow().isoformat()),
                        ),
                    )
                except Exception:
                    pass
            c.commit()


# ── Global DB instance ────────────────────────────────────────────────────────

_db = None


def get_db():
    global _db
    if _db is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _db


def init_db():
    """Initialize the global DB and migrate legacy JSON data on first run."""
    global _db
    cfg = load_db_config()
    db_path = cfg.get("db_path", "pktpcap.db")
    _db = Database(db_path)
    _migrate_legacy(_db)
    _ensure_admin(_db)


def _migrate_legacy(db: Database):
    """One-time migration from config.json / users.json → SQLite (runs only if settings table is empty)."""
    if db._conn().execute("SELECT COUNT(*) FROM settings").fetchone()[0] > 0:
        return  # Already migrated

    # Migrate app settings from old config.json
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            skip = {"db_type", "db_path"}
            to_migrate = {k: v for k, v in data.items() if k not in skip}
            if to_migrate:
                db.set_many_settings(to_migrate)
        except Exception:
            pass

    # Migrate users from old users.json
    legacy_users = BASE / "users.json"
    if legacy_users.exists():
        try:
            users = json.loads(legacy_users.read_text())
            with db._write_lock:
                c = db._conn()
                for u in users:
                    try:
                        c.execute(
                            "INSERT OR IGNORE INTO users "
                            "(username, email, role, status, password_hash, last_login, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                u["username"], u.get("email", ""), u.get("role", "viewer"),
                                u.get("status", "active"), u.get("password_hash", ""),
                                u.get("last_login"), u.get("created_at", datetime.datetime.utcnow().isoformat()),
                            ),
                        )
                    except Exception:
                        pass
                c.commit()
        except Exception:
            pass


def _ensure_admin(db: Database):
    """Create a default admin/admin account if no users exist."""
    if db._conn().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.create_user("admin", "admin@local", "admin", hash_password("admin"))
