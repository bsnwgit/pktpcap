#!/usr/bin/env python3
"""
pktPCAP -- standalone web service
Run: python server.py
"""

import json, logging, os, sys, webbrowser, threading, time, secrets, re as _re, socket, datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template, Response, session, redirect

from db import init_db, get_db, load_db_config, save_db_config, hash_password, check_password, Database
import backup_job

# ── Optional SAML support ─────────────────────────────────────────────────────
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    _SAML_AVAILABLE = True
except ImportError:
    _SAML_AVAILABLE = False

log = logging.getLogger("pktpcap.server")
_log_handler = None  # set at startup

BASE = Path(__file__).parent

# -- Live Feed Sessions --------------------------------------------------------

class FeedSession:
    """Buffers a live pcapng stream pushed from a remote tshark/Wireshark host."""
    MAX_BYTES = 200 * 1024 * 1024  # 200 MB per session

    def __init__(self, name, remote_addr):
        self.name           = name
        self.remote_addr    = remote_addr
        self.created_at     = time.time()
        self.last_seen      = time.time()
        self.connected      = False
        self._lock          = threading.Lock()
        self._buf           = bytearray()
        self.bytes_received = 0
        self.truncated      = False

    def append(self, data):
        with self._lock:
            self.last_seen       = time.time()
            self.bytes_received += len(data)
            remaining = self.MAX_BYTES - len(self._buf)
            if remaining > 0:
                self._buf.extend(data[:remaining])
                if len(data) > remaining:
                    self.truncated = True
            else:
                self.truncated = True

    def get_bytes(self):
        with self._lock:
            return bytes(self._buf)

    def clear(self):
        with self._lock:
            self._buf           = bytearray()
            self.bytes_received = 0
            self.truncated      = False

    def to_dict(self):
        with self._lock:
            return {
                "name":           self.name,
                "remote_addr":    self.remote_addr,
                "connected":      self.connected,
                "created_at":     self.created_at,
                "last_seen":      self.last_seen,
                "bytes_buffered": len(self._buf),
                "bytes_received": self.bytes_received,
                "duration":       self.last_seen - self.created_at,
                "truncated":      self.truncated,
            }

_feed_sessions = {}
_feed_sessions_lock = threading.Lock()

def _get_or_create_feed(name, remote_addr):
    with _feed_sessions_lock:
        if name not in _feed_sessions:
            _feed_sessions[name] = FeedSession(name, remote_addr)
        return _feed_sessions[name]


_CAPTURE_FILE_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,79}\.pcapng$")

def _captures_dir():
    """The configured on-disk capture directory (Settings > Captures > Storage
    path), or None if not configured. Feed sessions only ever live in memory
    until this is set -- nothing writes to disk without it."""
    storage_path = (load_config().get("storage_path") or "").strip()
    return Path(storage_path) if storage_path else None

def _save_feed_to_disk(feed_session):
    """Persist a finished feed session's buffered bytes to storage_path so it
    survives past the in-memory session (200MB cap, lost on restart/eviction).
    No-ops quietly if no storage_path is configured."""
    d = _captures_dir()
    if not d:
        return None
    data = feed_session.get_bytes()
    if not data:
        return None
    try:
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.fromtimestamp(feed_session.last_seen).strftime("%Y%m%d-%H%M%S")
        fname = f"{feed_session.name}_{ts}.pcapng"
        (d / fname).write_bytes(data)
        log.info("Saved capture %s (%d bytes) to %s", fname, len(data), d)
        return fname
    except OSError:
        log.exception("Failed to save feed %s to storage_path", feed_session.name)
        return None


def _ensure_suite_token():
    """Generate a suite token if one is not already set."""
    import sqlite3 as _sq_st, secrets as _sec_st
    _db_path = load_db_config().get("db_path", "pktpcap.db")
    if not os.path.isabs(_db_path):
        _db_path = str(BASE / _db_path)
    _conn = _sq_st.connect(_db_path)
    _row = _conn.execute("SELECT value FROM settings WHERE key='suite_token'").fetchone()
    if not _row or not (_row[0] or "").strip():
        _new = _sec_st.token_urlsafe(32)
        _conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('suite_token',?)", (_new,))
        _conn.commit()
        log.info("Generated suite_token for pktHub integration")
    _conn.close()

def _ensure_feed_token():
    db  = get_db()
    cfg = db.get_all_settings()
    if not cfg.get("feed_token"):
        db.set_many_settings({"feed_token": secrets.token_urlsafe(32)})

def _check_feed_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth[7:].strip()
    return bool(token) and token == load_config().get("feed_token", "")

def _get_server_ip():
    """Return the machine's primary LAN IP (non-loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _list_local_interfaces():
    """Return this server's own network interface names, e.g. for the
    Wireshark-GUI SSH-remote-capture tab where tshark runs on this host."""
    try:
        names = [n for _, n in socket.if_nameindex() if n != "lo"]
        return sorted(names)
    except (AttributeError, OSError):
        return []

# -- Flask app -----------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

def load_config():
    return get_db().get_all_settings()

def save_config(cfg):
    get_db().set_many_settings(cfg)

# ── Session secret key ────────────────────────────────────────────────────────

def _ensure_secret_key():
    db  = get_db()
    key = db.get_setting("flask_secret_key")
    if not key:
        key = secrets.token_hex(32)
        db.set_setting("flask_secret_key", key)
    app.secret_key = key

# ── Auth middleware ───────────────────────────────────────────────────────────

_AUTH_PUBLIC      = {"/login", "/api/login", "/api/logout", "/api/health", "/favicon.ico", "/favicon.svg"}
_AUTH_PUBLIC_PFX  = ("/static/", "/api/auth/saml", "/api/feed/")

@app.route("/api/health")
def api_health():
    """Public health endpoint — no auth required. Called by pktHub to check status."""
    return jsonify({"status": "ok", "app": "pktpcap", "version": "0.1.0"}), 200


@app.before_request
def require_login():
    path = request.path
    if path in _AUTH_PUBLIC or any(path.startswith(p) for p in _AUTH_PUBLIC_PFX):
        return None

    cfg = load_config()
    # Both auth methods off → auto-login as the default admin account
    if not cfg.get("local_auth_enabled", True) and not cfg.get("okta_saml_enabled", False):
        if not session.get("user_id"):
            admin = get_db()._conn().execute(
                "SELECT id, role FROM users WHERE is_default_admin = 1 AND status = 'active' LIMIT 1"
            ).fetchone()
            if not admin:
                # No user explicitly flagged (or the flagged account was deactivated/deleted) —
                # fall back to the first active admin so this never dead-ends into a lockout.
                admin = get_db()._conn().execute(
                    "SELECT id, role FROM users WHERE role = 'admin' AND status = 'active' ORDER BY id ASC LIMIT 1"
                ).fetchone()
            if admin:
                session["user_id"]    = admin["id"]
                session["role"]       = admin["role"]
                session["login_time"] = time.time()
        return None

    # ── pktHub suite-token auth ─────────────────────────────────────────
    # X-Suite-Token is sent by pktHub proxy on every proxied request.
    # Validate it and establish a Flask session so normal auth checks pass.
    _suite_tk = request.headers.get("X-Suite-Token", "")
    if _suite_tk:
        _st_cfg = load_config()
        _expected = _st_cfg.get("suite_token", "")
        if _expected and _suite_tk == _expected:
            _hub_user = request.headers.get("X-Suite-User", "hub_user")
            _hub_role = request.headers.get("X-Suite-Role", "viewer")
            session["user_id"] = _hub_user
            session["role"] = "admin" if _hub_role == "admin" else "viewer"
            session["login_time"] = time.time()
            return None

    uid = session.get("user_id")
    if not uid:
        if path.startswith("/api/"):
            return jsonify({"error": "Unauthorized", "login_url": "/login"}), 401
        return redirect("/login")

    timeout = int(cfg.get("session_timeout_minutes", 480)) * 60
    if time.time() - float(session.get("login_time", 0)) > timeout:
        session.clear()
        if path.startswith("/api/"):
            return jsonify({"error": "Session expired", "login_url": "/login"}), 401
        return redirect("/login?error=session_expired")

    session["login_time"] = time.time()

# -- Routes --------------------------------------------------------------------

@app.route("/")
def index():
    resp = send_from_directory(BASE / "static", "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp

@app.route("/favicon.ico")
def favicon_ico():
    return send_from_directory(BASE / "static", "favicon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/favicon.svg")
def favicon_svg():
    return send_from_directory(BASE / "static", "favicon.svg", mimetype="image/svg+xml")

@app.route("/settings")
def settings_page():
    if session.get("role") != "admin":
        return redirect("/")
    cfg = load_config()
    return render_template("settings.html", app_name=cfg.get("app_name", "pktPCAP"))

# -- Auth: login / logout / SAML -----------------------------------------------

@app.route("/login")
def login_page():
    if session.get("user_id"):
        return redirect("/")
    cfg = load_config()
    saml_enabled       = bool(cfg.get("okta_saml_enabled") and cfg.get("okta_sso_url"))
    local_auth_enabled = bool(cfg.get("local_auth_enabled", True))
    if not local_auth_enabled and not saml_enabled:
        # Every auth method is off — before_request will auto-login the next
        # request, so send the browser straight to the app instead of a dead-end form.
        return redirect("/")
    error_map = {
        "session_expired": "Your session has expired. Please sign in again.",
        "user_not_found":  "User not found. Contact your administrator.",
        "account_disabled":"Your account is disabled. Contact your administrator.",
        "saml_auth_failed":"Okta authentication failed. Please try again.",
    }
    raw_err = request.args.get("error", "")
    error   = error_map.get(raw_err, raw_err.replace("_", " ") if raw_err else "")
    return render_template("login.html",
                           app_name=cfg.get("app_name", "pktPCAP"),
                           saml_enabled=saml_enabled,
                           local_auth_enabled=local_auth_enabled,
                           error=error)

@app.route("/api/login", methods=["POST"])
def api_login():
    body     = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    cfg = load_config()
    if not cfg.get("local_auth_enabled", True):
        return jsonify({"ok": False, "error": "Local authentication is disabled"}), 403
    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required"}), 400
    db   = get_db()
    user = db.get_user_by_username(username)
    if not user or not check_password(password, user.get("password_hash", "")):
        return jsonify({"ok": False, "error": "Invalid username or password"}), 401
    if (user.get("status") or "active") != "active":
        return jsonify({"ok": False, "error": "Account is disabled"}), 403
    session.permanent = True
    session["user_id"]    = user["id"]
    session["username"]   = user["username"]
    session["role"]       = user["role"]
    session["login_time"] = time.time()
    db.update_user(user["id"], {"last_login": datetime.datetime.utcnow().isoformat()})
    return jsonify({"ok": True, "role": user["role"]})

@app.route("/api/logout", methods=["POST", "GET"])
def api_logout():
    session.clear()
    return redirect("/login")

@app.route("/api/auth/current-user")
def api_current_user():
    if not session.get("user_id"):
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "id":       session["user_id"],
        "username": session.get("username"),
        "role":     session.get("role"),
    })

# -- SAML helpers --------------------------------------------------------------

def _build_saml_settings():
    cfg  = load_config()
    base = request.url_root.rstrip("/")
    ssl  = bool(cfg.get("ssl_enabled"))
    return {
        "strict": ssl,
        "debug":  False,
        "sp": {
            "entityId": cfg.get("okta_sp_entity_id") or f"{base}/api/auth/saml/metadata",
            "assertionConsumerService": {
                "url":     f"{base}/api/auth/saml/callback",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url":     f"{base}/api/auth/saml/slo",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert":  cfg.get("okta_sp_cert", ""),
            "privateKey": cfg.get("okta_sp_key", ""),
        },
        "idp": {
            "entityId": cfg.get("okta_entity_id", ""),
            "singleSignOnService": {
                "url":     cfg.get("okta_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url":     cfg.get("okta_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.get("okta_cert", ""),
        },
    }

def _init_saml_auth():
    req = {
        "https":       "on" if request.is_secure else "off",
        "http_host":   request.host,
        "server_port": request.environ.get("SERVER_PORT", "443" if request.is_secure else "80"),
        "script_name": request.path,
        "get_data":    request.args.to_dict(),
        "post_data":   request.form.to_dict(),
        "query_string": request.query_string.decode("utf-8"),
    }
    return OneLogin_Saml2_Auth(req, _build_saml_settings())

@app.route("/api/auth/saml/login")
def saml_login():
    if not _SAML_AVAILABLE:
        return "SAML library not installed on this server", 500
    cfg = load_config()
    if not cfg.get("okta_saml_enabled"):
        return "SAML SSO is not enabled", 400
    auth = _init_saml_auth()
    return redirect(auth.login())

@app.route("/api/auth/saml/callback", methods=["POST"])
def saml_callback():
    if not _SAML_AVAILABLE:
        return "SAML library not installed", 500
    auth = _init_saml_auth()
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        log.error("SAML errors: %s — %s", errors, auth.get_last_error_reason())
        return redirect("/login?error=saml_auth_failed")
    if not auth.is_authenticated():
        return redirect("/login?error=saml_auth_failed")
    name_id    = auth.get_nameid()   # Okta sends email as NameID
    attributes = auth.get_attributes()
    log.warning("SAML login NameID=%s attributes=%s", name_id, attributes)

    # Extract role from Okta attributes (checks common attribute names)
    _VALID_ROLES = {"admin", "analyst", "viewer"}
    okta_role = None
    for attr_key in ("role", "Role", "userRole", "pktpcap_role", "appRole"):
        val = attributes.get(attr_key)
        if val:
            candidate = (val[0] if isinstance(val, list) else val).lower().strip()
            if candidate in _VALID_ROLES:
                okta_role = candidate
                break

    db   = get_db()
    user = db.get_user_by_email(name_id) or db.get_user_by_username(name_id)
    if not user:
        # Auto-provision on first SAML login — default admin since Okta access = trusted
        role = okta_role or "admin"
        email    = name_id if "@" in name_id else ""
        username = email.split("@")[0] if email else name_id
        base = username; suffix = 0
        while db.get_user_by_username(username):
            suffix += 1; username = f"{base}{suffix}"
        log.info("SAML auto-provision: user=%s email=%s role=%s", username, email, role)
        db.create_user(username=username, email=email, role=role, password_hash="")
        user = db.get_user_by_email(name_id) or db.get_user_by_username(username)
        if not user:
            log.error("SAML auto-provision failed for %s", name_id)
            return redirect("/login?error=provision_failed")
    else:
        # Sync role from Okta on every login if Okta sends one
        if okta_role and user.get("role") != okta_role:
            log.info("SAML role sync: user=%s %s -> %s", user["username"], user.get("role"), okta_role)
            db.update_user(user["id"], {"role": okta_role})
            user = db.get_user_by_email(name_id) or db.get_user_by_username(user["username"])

    if (user.get("status") or "active") != "active":
        return redirect("/login?error=account_disabled")
    session.permanent = True
    session["user_id"]    = user["id"]
    session["username"]   = user["username"]
    session["role"]       = user["role"]
    session["login_time"] = time.time()
    db.update_user(user["id"], {"last_login": datetime.datetime.utcnow().isoformat()})
    return redirect("/")

@app.route("/api/auth/saml/metadata")
def saml_metadata():
    if not _SAML_AVAILABLE:
        return "SAML library not installed", 500
    settings = OneLogin_Saml2_Settings(_build_saml_settings(), sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    return Response(metadata, mimetype="text/xml")

# -- API: settings -------------------------------------------------------------

@app.route("/api/settings", methods=["GET"])
def get_settings():
    cfg    = load_config()
    masked = dict(cfg)
    BULLET = "•"
    for k in ("anthropic_key", "openai_key", "notify_email_password",
              "notify_pagerduty_integration_key", "notify_tracecat_api_token",
              "lucid_api_token"):
        if masked.get(k):
            v = str(masked[k])
            masked[k] = v[:8] + BULLET * max(0, len(v) - 8)
    masked["server_ip"] = _get_server_ip()
    return jsonify(masked)

@app.route("/api/settings", methods=["POST"])
def post_settings():
    body = request.get_json(force=True)
    db   = get_db()
    cfg  = db.get_all_settings()
    BULLET = "•"

    for field in (
        "app_name", "provider", "anthropic_model", "openai_model",
        "base_url", "timezone", "storage_path", "backup_path",
        "notify_slack_channel", "notify_slack_webhook_url",
        "notify_email_smtp_host", "notify_email_from", "notify_email_default_to",
        "notify_email_username", "notify_webhook_url", "notify_webhook_method",
        "notify_webhook_payload_template", "notify_tracecat_webhook_url",
        "okta_metadata_xml", "okta_entity_id", "okta_sso_url", "okta_cert",
        "pfx_path", "pfx_passphrase", "pem_cert_path", "pem_key_path",
        "ssl_cert", "ssl_key",
    ):
        if field in body:
            cfg[field] = body[field]

    cfg["app_name"] = cfg.get("app_name") or "pktPCAP"

    for field, default in (("port", 8765), ("max_upload_mb", 500),
                           ("storage_quota_gb", 50), ("retention_days", 90),
                           ("backup_interval_hours", 24), ("backup_rotation", 7),
                           ("session_timeout_minutes", 480),
                           ("notify_email_smtp_port", 587)):
        if field in body:
            try:
                cfg[field] = int(body[field])
            except (ValueError, TypeError):
                cfg[field] = default

    for field in (
        "ssl_enabled", "auto_purge", "auto_backup", "backup_include_captures",
        "local_auth_enabled", "okta_saml_enabled", "notify_smtp_tls",
        "notify_slack_enabled", "notify_email_enabled", "notify_pagerduty_enabled",
        "notify_webhook_enabled", "notify_tracecat_enabled", "pfx_mode",
        "wireshark_capture_enabled", "tshark_capture_enabled",
    ):
        if field in body:
            cfg[field] = bool(body[field])

    for k in ("anthropic_key", "openai_key", "notify_email_password",
              "notify_pagerduty_integration_key", "notify_tracecat_api_token",
              "lucid_api_token"):
        v = body.get(k, "")
        if v and BULLET not in str(v):
            cfg[k] = v

    db.set_many_settings(cfg)
    return jsonify({"ok": True, "port": cfg.get("port", 8765)})

# -- API: per-user external lookup API keys --------------------------------------

SUPPORTED_KEY_PROVIDERS = {
    "abuseipdb":      "AbuseIPDB",
    "ipqualityscore": "IPQualityScore",
    "ipinfo":         "ipinfo.io",
    "ipapi_is":       "ipapi.is",
    "mxtoolbox":      "MXToolbox",
}
_TEST_IP = "8.8.8.8"

# The ipinfo.io response sections a user can individually show/hide in the IP
# Lookup modal. Display preference only — ipinfo.io always returns whatever
# the account's plan unlocks; this just controls what renders.
IPINFO_FIELDS = ["geolocation", "asn", "company", "privacy", "abuse", "domains"]

# Same idea for ipapi.is — its response sections a user can individually
# show/hide. "detection" covers the is_vpn/is_proxy/is_tor/is_datacenter/
# is_abuser/is_mobile/is_satellite/is_crawler/is_bogon flags plus the vpn{}
# detail object.
IPAPI_IS_FIELDS = ["geolocation", "asn", "company", "detection", "abuse"]

# MXToolbox only auto-wires 3 of its 21 commands into the IP Lookup modal
# (see get_ip_info() below) — the rest are domain/email record checks and
# active probes, reachable only via the generic /api/mxtoolbox/lookup
# endpoint, not this per-IP lookup. These 3 keys match the mxtoolbox result
# dict's own field names.
MXTOOLBOX_FIELDS = ["ptr", "asn", "blacklist"]

@app.route("/api/whoami", methods=["GET"])
def whoami():
    username = session.get("username")
    if not username:
        uid = session.get("user_id")
        if isinstance(uid, int):
            row = get_db()._conn().execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
            username = row["username"] if row else uid
        else:
            username = uid
    return jsonify({"username": username})

@app.route("/api/user-api-keys", methods=["GET"])
def get_user_api_keys():
    username = session.get("username") or session.get("user_id")
    stored = get_db().get_user_api_keys(username)
    return jsonify([
        {
            "provider": p, "label": label,
            "api_key": stored.get(p, {}).get("api_key", ""),
            "updated_at": stored.get(p, {}).get("updated_at"),
            "enabled_fields": stored.get(p, {}).get("enabled_fields"),
            "free_tier": stored.get(p, {}).get("free_tier", False),
        }
        for p, label in SUPPORTED_KEY_PROVIDERS.items()
    ])

@app.route("/api/user-api-keys/ipinfo/fields", methods=["PUT"])
def set_ipinfo_fields():
    username = session.get("username") or session.get("user_id")
    fields = (request.get_json(silent=True) or {}).get("enabled_fields", [])
    unknown = [f for f in fields if f not in IPINFO_FIELDS]
    if unknown:
        return jsonify({"error": f"Unknown field(s): {', '.join(unknown)}"}), 400
    row = get_db().set_ipinfo_fields(username, fields)
    return jsonify({
        "provider": "ipinfo", "label": SUPPORTED_KEY_PROVIDERS["ipinfo"],
        "api_key": row["api_key"], "updated_at": row["updated_at"],
        "enabled_fields": row["enabled_fields"],
    })

@app.route("/api/user-api-keys/ipapi_is/fields", methods=["PUT"])
def set_ipapi_is_fields():
    username = session.get("username") or session.get("user_id")
    fields = (request.get_json(silent=True) or {}).get("enabled_fields", [])
    unknown = [f for f in fields if f not in IPAPI_IS_FIELDS]
    if unknown:
        return jsonify({"error": f"Unknown field(s): {', '.join(unknown)}"}), 400
    row = get_db().set_ipapi_is_fields(username, fields)
    return jsonify({
        "provider": "ipapi_is", "label": SUPPORTED_KEY_PROVIDERS["ipapi_is"],
        "api_key": row["api_key"], "updated_at": row["updated_at"],
        "enabled_fields": row["enabled_fields"],
    })

@app.route("/api/user-api-keys/ipapi_is/free-tier", methods=["PUT"])
def set_ipapi_is_free_tier():
    username = session.get("username") or session.get("user_id")
    free_tier = bool((request.get_json(silent=True) or {}).get("free_tier", False))
    row = get_db().set_ipapi_is_free_tier(username, free_tier)
    return jsonify({
        "provider": "ipapi_is", "label": SUPPORTED_KEY_PROVIDERS["ipapi_is"],
        "api_key": row["api_key"], "updated_at": row["updated_at"],
        "enabled_fields": row["enabled_fields"], "free_tier": row["free_tier"],
    })

@app.route("/api/user-api-keys/mxtoolbox/fields", methods=["PUT"])
def set_mxtoolbox_fields():
    username = session.get("username") or session.get("user_id")
    fields = (request.get_json(silent=True) or {}).get("enabled_fields", [])
    unknown = [f for f in fields if f not in MXTOOLBOX_FIELDS]
    if unknown:
        return jsonify({"error": f"Unknown field(s): {', '.join(unknown)}"}), 400
    row = get_db().set_mxtoolbox_fields(username, fields)
    return jsonify({
        "provider": "mxtoolbox", "label": SUPPORTED_KEY_PROVIDERS["mxtoolbox"],
        "api_key": row["api_key"], "updated_at": row["updated_at"],
        "enabled_fields": row["enabled_fields"],
    })

@app.route("/api/user-api-keys/<provider>", methods=["PUT"])
def set_user_api_key(provider):
    if provider not in SUPPORTED_KEY_PROVIDERS:
        return jsonify({"error": f"Unknown provider: {provider}"}), 404
    username = session.get("username") or session.get("user_id")
    key = (request.get_json(silent=True) or {}).get("api_key", "").strip()
    get_db().set_user_api_key(username, provider, key)
    return jsonify({"provider": provider, "label": SUPPORTED_KEY_PROVIDERS[provider], "api_key": key})

@app.route("/api/user-api-keys/<provider>/test", methods=["POST"])
def test_user_api_key(provider):
    if provider not in SUPPORTED_KEY_PROVIDERS:
        return jsonify({"error": f"Unknown provider: {provider}"}), 404
    key = (request.get_json(silent=True) or {}).get("api_key", "").strip()
    if not key:
        return jsonify({"status": "skipped", "detail": "No API key entered"})

    import urllib.request, urllib.error, urllib.parse

    def _get(url, params=None, headers=None, timeout=10):
        if params:
            url = url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    try:
        if provider == "abuseipdb":
            status, text = _get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": _TEST_IP, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            if status == 200:
                return jsonify({"status": "ok", "detail": "Key is valid"})
            return jsonify({"status": "failed", "detail": f"AbuseIPDB returned HTTP {status}: {text[:200]}"})

        elif provider == "ipinfo":
            status, text = _get(f"https://ipinfo.io/{_TEST_IP}/json", params={"token": key})
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if status == 200 and "error" not in data:
                return jsonify({"status": "ok", "detail": "Key is valid"})
            err = data.get("error")
            detail = err.get("message") if isinstance(err, dict) else err
            return jsonify({"status": "failed", "detail": detail or f"ipinfo.io returned HTTP {status}: {text[:200]}"})

        elif provider == "ipqualityscore":
            status, text = _get(f"https://ipqualityscore.com/api/json/ip/{urllib.parse.quote(key, safe='')}/{_TEST_IP}")
            try:
                data = json.loads(text) if status == 200 else {}
            except Exception:
                data = {}
            if status == 200 and data.get("success"):
                return jsonify({"status": "ok", "detail": "Key is valid"})
            return jsonify({"status": "failed", "detail": data.get("message") or f"IPQualityScore returned HTTP {status}: {text[:200]}"})

        elif provider == "mxtoolbox":
            status, text = _get(
                "https://api.mxtoolbox.com/api/v1/Lookup/ptr/",
                params={"argument": _TEST_IP},
                headers={"Authorization": key, "Accept": "application/json"},
            )
            if status == 200:
                return jsonify({"status": "ok", "detail": "Key is valid"})
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            errors = data.get("Errors") if isinstance(data, dict) else None
            detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
            return jsonify({"status": "failed", "detail": detail or f"MXToolbox returned HTTP {status}: {text[:200]}"})

        elif provider == "ipapi_is":
            status, text = _get("https://api.ipapi.is/", params={"q": _TEST_IP, "key": key})
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if status == 200 and not data.get("error"):
                return jsonify({"status": "ok", "detail": "Key is valid"})
            return jsonify({"status": "failed", "detail": data.get("error") or f"ipapi.is returned HTTP {status}: {text[:200]}"})
    except Exception as exc:
        return jsonify({"status": "failed", "detail": f"Request error: {exc}"})

    return jsonify({"status": "failed", "detail": "Unhandled provider"})

# -- API: combined public-IP intelligence lookup ---------------------------------
# GET /api/ip-info/<ip> — ipinfo.io + ipapi.is + AbuseIPDB + MXToolbox (ptr/asn/
# blacklist) using the current user's own stored keys. Private/loopback/reserved
# addresses are rejected — external providers have nothing useful to say about
# them. Sequential (not concurrent) calls, matching this file's existing sync
# urllib style — there's no event loop here to gather() against.

@app.route("/api/ip-info/<ip>", methods=["GET"])
def get_ip_info(ip):
    import ipaddress as _ipaddress
    try:
        ip_obj = _ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Invalid IP address: {ip}"}), 400
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        return jsonify({"error": "IP info lookup is only available for public addresses"}), 400

    import urllib.request, urllib.error, urllib.parse

    def _get(url, params=None, headers=None, timeout=10):
        if params:
            url = url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _json(text):
        try:
            return json.loads(text)
        except Exception:
            return {}

    def _mxtoolbox_call(command, argument, key):
        try:
            status, text = _get(
                f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/",
                params={"argument": argument},
                headers={"Authorization": key, "Accept": "application/json"},
            )
            data = _json(text)
            if status == 200:
                return data, None
            errors = data.get("Errors") if isinstance(data, dict) else None
            detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
            return None, detail or f"MXToolbox returned HTTP {status}: {text[:200]}"
        except Exception as exc:
            return None, f"Request error: {exc}"

    username = session.get("username") or session.get("user_id")
    stored = get_db().get_user_api_keys(username)
    keys = {p: v.get("api_key", "") for p, v in stored.items()}

    result = {
        "ip": ip,
        "ipinfo_enabled_fields": stored.get("ipinfo", {}).get("enabled_fields"),
        "ipapi_is_enabled_fields": stored.get("ipapi_is", {}).get("enabled_fields"),
        "mxtoolbox_enabled_fields": stored.get("mxtoolbox", {}).get("enabled_fields"),
    }

    ipinfo_key = keys.get("ipinfo", "")
    if ipinfo_key:
        try:
            status, text = _get(f"https://ipinfo.io/{ip}/json", params={"token": ipinfo_key})
            data = _json(text)
            if status == 200 and "error" not in data:
                result["ipinfo"] = data
            else:
                err = data.get("error")
                result["ipinfo_error"] = (err.get("message") if isinstance(err, dict) else err) or f"ipinfo.io returned HTTP {status}: {text[:200]}"
        except Exception as exc:
            result["ipinfo_error"] = f"Request error: {exc}"
    else:
        result["ipinfo_error"] = "No ipinfo.io key configured — add one in Settings → User Keys"

    ipapi_is_key = keys.get("ipapi_is", "")
    ipapi_is_free_tier = bool(stored.get("ipapi_is", {}).get("free_tier"))
    if ipapi_is_key or ipapi_is_free_tier:
        try:
            # Free tier deliberately omits the key param entirely rather than
            # sending an empty one — matches ipapi.is's own anonymous/no-key
            # usage (1,000 req/day, no signup) rather than an invalid-key call.
            params = {"q": ip} if ipapi_is_free_tier else {"q": ip, "key": ipapi_is_key}
            status, text = _get("https://api.ipapi.is/", params=params)
            data = _json(text)
            if status == 200 and not data.get("error"):
                result["ipapi_is"] = data
            else:
                result["ipapi_is_error"] = data.get("error") or f"ipapi.is returned HTTP {status}: {text[:200]}"
        except Exception as exc:
            result["ipapi_is_error"] = f"Request error: {exc}"
    else:
        result["ipapi_is_error"] = "No ipapi.is key configured — add one in Settings → User Keys, or enable the free tier"

    abuseipdb_key = keys.get("abuseipdb", "")
    if abuseipdb_key:
        try:
            status, text = _get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": abuseipdb_key, "Accept": "application/json"},
            )
            data = _json(text)
            if status == 200:
                result["abuseipdb"] = data.get("data")
            else:
                errors = data.get("errors") or []
                result["abuseipdb_error"] = (errors[0].get("detail") if errors else None) or f"AbuseIPDB returned HTTP {status}: {text[:200]}"
        except Exception as exc:
            result["abuseipdb_error"] = f"Request error: {exc}"
    else:
        result["abuseipdb_error"] = "No AbuseIPDB key configured — add one in Settings → User Keys"

    mxtoolbox_key = keys.get("mxtoolbox", "")
    if mxtoolbox_key:
        ptr, ptr_err = _mxtoolbox_call("ptr", ip, mxtoolbox_key)
        asn, asn_err = _mxtoolbox_call("asn", ip, mxtoolbox_key)
        blacklist, blacklist_err = _mxtoolbox_call("blacklist", ip, mxtoolbox_key)
        result["mxtoolbox"] = {
            "ptr": ptr, "ptr_error": ptr_err,
            "asn": asn, "asn_error": asn_err,
            "blacklist": blacklist, "blacklist_error": blacklist_err,
        }
    else:
        result["mxtoolbox_error"] = "No MXToolbox key configured — add one in Settings → User Keys"

    return jsonify(result)

# -- API: generic MXToolbox command passthrough -----------------------------------
# POST /api/mxtoolbox/lookup — every command MXToolbox's API supports, not
# just the ptr/asn/blacklist subset auto-wired into GET /api/ip-info/<ip>:
# DNS/email-record checks (a, aaaa, bimi, dkim, dmarc, dns, mta-sts, mx, soa,
# spf, tlsrpt, txt) and active network probes MXToolbox's own infrastructure
# runs against the target (blacklist, http, https, ping, smtp, tcp, trace).
# No response modeling — passes MXToolbox's raw JSON straight through.

_MXTOOLBOX_DNS_COMMANDS = {"a", "aaaa", "asn", "bimi", "dkim", "dmarc", "dns", "mta-sts", "mx", "ptr", "soa", "spf", "tlsrpt", "txt"}
_MXTOOLBOX_NETWORK_COMMANDS = {"blacklist", "http", "https", "ping", "smtp", "tcp", "trace"}
_MXTOOLBOX_ALL_COMMANDS = _MXTOOLBOX_DNS_COMMANDS | _MXTOOLBOX_NETWORK_COMMANDS

@app.route("/api/mxtoolbox/lookup", methods=["POST"])
def mxtoolbox_lookup():
    body = request.get_json(silent=True) or {}
    command = (body.get("command") or "").strip().lower()
    argument = (body.get("argument") or "").strip()
    port = body.get("port")

    if command not in _MXTOOLBOX_ALL_COMMANDS:
        return jsonify({"error": f"Unsupported MXToolbox command: {command}"}), 400
    if not argument:
        return jsonify({"error": "argument is required"}), 400
    if command == "dkim" and ":" not in argument:
        return jsonify({"error": "dkim requires argument in 'domain:selector' format"}), 400
    if command == "tcp" and not port:
        return jsonify({"error": "tcp requires a port"}), 400

    username = session.get("username") or session.get("user_id")
    stored = get_db().get_user_api_keys(username)
    key = stored.get("mxtoolbox", {}).get("api_key", "")
    if not key:
        return jsonify({"error": "No MXToolbox key configured — add one in Settings → User Keys"}), 400

    import urllib.request, urllib.error, urllib.parse

    params = {"argument": argument}
    if command == "tcp":
        params["port"] = port

    url = f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method="GET", headers={"Authorization": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, text = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors="replace")
    except Exception as exc:
        return jsonify({"error": f"Request error: {exc}"}), 502

    try:
        data = json.loads(text)
    except Exception:
        data = {"raw": text[:2000]}

    if status != 200:
        errors = data.get("Errors") if isinstance(data, dict) else None
        detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
        return jsonify({"error": detail or f"MXToolbox returned HTTP {status}"}), status

    return jsonify(data)

# -- API: notification test -----------------------------------------------------

_TEST_SUBJECT = "pktPCAP Test"
_TEST_MESSAGE = "pktPCAP test notification — your configuration is working correctly."

@app.route("/api/notifications/test", methods=["POST"])
def test_notification():
    """Send a test notification on the specified channel using saved settings."""
    import urllib.request, urllib.error

    body    = request.get_json(force=True)
    channel = body.get("channel", "")
    valid   = {"slack", "email", "pagerduty", "webhook", "tracecat"}
    if channel not in valid:
        return jsonify({"status": "failed", "detail": f"Unknown channel: {channel}"}), 400

    cfg = load_config()

    def _post_json(url, payload, headers=None, timeout=10):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                      headers={"Content-Type": "application/json", **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")

    try:
        if channel == "slack":
            if not cfg.get("notify_slack_enabled"):
                return jsonify({"status": "skipped", "detail": "Slack is not enabled"})
            url = cfg.get("notify_slack_webhook_url") or ""
            if not url:
                return jsonify({"status": "skipped", "detail": "No webhook URL configured"})
            status, text = _post_json(url, {"text": f":white_circle: *{_TEST_SUBJECT}*\n{_TEST_MESSAGE}"})
            if status == 200:
                return jsonify({"status": "sent", "detail": "Slack message delivered"})
            return jsonify({"status": "failed", "detail": f"Slack returned HTTP {status}: {text[:200]}"})

        elif channel == "email":
            if not cfg.get("notify_email_enabled"):
                return jsonify({"status": "skipped", "detail": "Email is not enabled"})
            host      = cfg.get("notify_email_smtp_host") or ""
            port      = int(cfg.get("notify_email_smtp_port") or 587)
            use_tls   = cfg.get("notify_smtp_tls")
            use_tls   = True if use_tls is None else bool(use_tls)
            username  = cfg.get("notify_email_username") or ""
            password  = cfg.get("notify_email_password") or ""
            from_addr = cfg.get("notify_email_from") or "pktpcap@localhost"
            to_addr   = cfg.get("notify_email_default_to") or ""
            to_addrs  = [a.strip() for a in to_addr.split(",") if a.strip()]
            if not host or not to_addrs:
                return jsonify({"status": "skipped", "detail": "SMTP host or recipient not configured"})
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(f"pktPCAP Test Notification\n\n{_TEST_MESSAGE}", "plain")
            msg["Subject"] = f"[{_TEST_SUBJECT}]"
            msg["From"]    = from_addr
            msg["To"]      = ", ".join(to_addrs)
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                if use_tls:
                    smtp.starttls()
                if username:
                    smtp.login(username, password)
                smtp.sendmail(from_addr, to_addrs, msg.as_string())
            return jsonify({"status": "sent", "detail": f"Email sent to {', '.join(to_addrs)}"})

        elif channel == "pagerduty":
            if not cfg.get("notify_pagerduty_enabled"):
                return jsonify({"status": "skipped", "detail": "PagerDuty is not enabled"})
            key = cfg.get("notify_pagerduty_integration_key") or ""
            if not key:
                return jsonify({"status": "skipped", "detail": "No integration key configured"})
            payload = {
                "routing_key": key, "event_action": "trigger",
                "payload": {"summary": f"[{_TEST_SUBJECT}] {_TEST_MESSAGE}", "severity": "info", "source": "pktpcap"},
            }
            status, text = _post_json("https://events.pagerduty.com/v2/enqueue", payload)
            if status in (200, 202):
                return jsonify({"status": "sent", "detail": "PagerDuty event triggered"})
            return jsonify({"status": "failed", "detail": f"PagerDuty returned HTTP {status}: {text[:200]}"})

        elif channel == "webhook":
            if not cfg.get("notify_webhook_enabled"):
                return jsonify({"status": "skipped", "detail": "Webhook is not enabled"})
            url      = cfg.get("notify_webhook_url") or ""
            method   = (cfg.get("notify_webhook_method") or "POST").upper()
            template = cfg.get("notify_webhook_payload_template") or '{"text":"{{message}}"}'
            if not url:
                return jsonify({"status": "skipped", "detail": "No webhook URL configured"})
            rendered = (template
                        .replace("{{message}}", _TEST_MESSAGE)
                        .replace("{{alert_name}}", _TEST_SUBJECT)
                        .replace("{{severity}}", "info")
                        .replace("{{fired_at}}", datetime.datetime.now(datetime.timezone.utc).isoformat()))
            try:
                payload = json.loads(rendered)
            except Exception as e:
                return jsonify({"status": "failed", "detail": f"Template render error: {e}"})
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, method=method,
                                          headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return jsonify({"status": "sent", "detail": f"Webhook returned HTTP {resp.status}"})
            except urllib.error.HTTPError as e:
                return jsonify({"status": "failed", "detail": f"Webhook returned HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"})

        elif channel == "tracecat":
            if not cfg.get("notify_tracecat_enabled"):
                return jsonify({"status": "skipped", "detail": "Tracecat is not enabled"})
            url   = cfg.get("notify_tracecat_webhook_url") or ""
            token = cfg.get("notify_tracecat_api_token") or ""
            if not url:
                return jsonify({"status": "skipped", "detail": "No webhook URL configured"})
            payload = {
                "source": "pktpcap", "event_id": 0, "alert_name": _TEST_SUBJECT,
                "severity": "info", "message": _TEST_MESSAGE,
                "fired_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "details": {"test": True},
            }
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            status, text = _post_json(url, payload, headers=headers)
            if status < 300:
                return jsonify({"status": "sent", "detail": f"Tracecat returned HTTP {status}"})
            return jsonify({"status": "failed", "detail": f"Tracecat returned HTTP {status}: {text[:200]}"})

    except urllib.error.HTTPError as e:
        return jsonify({"status": "failed", "detail": f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"})
    except urllib.error.URLError as e:
        return jsonify({"status": "failed", "detail": f"Connection error: {e.reason}"})
    except Exception as e:
        log.exception("Test notification failed")
        return jsonify({"status": "failed", "detail": str(e)[:300]})

# -- API: database config ------------------------------------------------------

@app.route("/api/db-config", methods=["GET"])
def get_db_config():
    return jsonify(load_db_config())

@app.route("/api/db-config/test", methods=["POST"])
def test_db_config():
    body    = request.get_json(force=True)
    db_type = body.get("db_type", "sqlite")
    db_path = body.get("db_path", "pktpcap.db")
    if db_type != "sqlite":
        return jsonify({"ok": False, "error": "Only SQLite is supported"}), 400
    try:
        test_db = Database(db_path)
        test_db._conn().execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/db-config", methods=["POST"])
def post_db_config():
    body    = request.get_json(force=True)
    db_type = body.get("db_type", "sqlite")
    db_path = (body.get("db_path") or "pktpcap.db").strip()
    if db_type != "sqlite":
        return jsonify({"ok": False, "error": "Only SQLite is supported currently"}), 400
    if not db_path:
        return jsonify({"ok": False, "error": "db_path required"}), 400
    try:
        new_db = Database(db_path)
        new_db._conn().execute("SELECT 1")
    except Exception as e:
        return jsonify({"ok": False, "error": "Cannot open DB: {}".format(e)}), 400
    try:
        export = get_db().export_all()
        new_db.import_all(export)
    except Exception as e:
        return jsonify({"ok": False, "error": "Migration failed: {}".format(e)}), 500
    save_db_config(db_type, db_path)
    import db as _db_module
    _db_module._db = new_db
    return jsonify({"ok": True})

# -- API: backup ----------------------------------------------------------------

@app.route("/api/backup/run", methods=["POST"])
def api_run_backup():
    try:
        result = backup_job.run_backup(load_config(), load_db_config().get("db_path", "pktpcap.db"))
        return jsonify({"ok": True, **result})
    except Exception as e:
        log.exception("Backup run failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/backup/list", methods=["GET"])
def api_list_backups():
    return jsonify(backup_job.list_backups(load_config()))

# -- API: AI proxy -------------------------------------------------------------

@app.route("/api/ai", methods=["POST"])
def ai_call():
    cfg      = load_config()
    body     = request.get_json(force=True)
    prompt   = body.get("prompt", "")
    data     = body.get("data", [])
    provider = cfg.get("provider", "anthropic")
    user_content = "\n\n".join(data) if data else ""
    full_message = (prompt + "\n\n" + user_content).strip() if user_content else prompt
    try:
        if provider == "anthropic":
            key   = cfg.get("anthropic_key", "")
            model = cfg.get("anthropic_model", "claude-opus-4-8")
            if not key:
                return jsonify({"error": "Anthropic API key not configured. Go to /settings to add it."}), 400
            import anthropic as _ant
            client = _ant.Anthropic(api_key=key)
            resp = client.messages.create(model=model, max_tokens=2048,
                                          messages=[{"role": "user", "content": full_message}])
            text = resp.content[0].text if resp.content else ""
        elif provider == "openai":
            key   = cfg.get("openai_key", "")
            model = cfg.get("openai_model", "gpt-4o")
            if not key:
                return jsonify({"error": "OpenAI API key not configured. Go to /settings to add it."}), 400
            import openai as _oai
            client = _oai.OpenAI(api_key=key)
            resp = client.chat.completions.create(model=model, max_tokens=2048,
                                                  messages=[{"role": "user", "content": full_message}])
            text = resp.choices[0].message.content or ""
        else:
            return jsonify({"error": "Unknown provider: {}".format(provider)}), 400
        return jsonify({"content": text})
    except Exception as e:
        log.exception("AI call failed")
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/test", methods=["POST"])
def ai_test():
    cfg      = load_config()
    body     = request.get_json(force=True)
    provider = body.get("provider", cfg.get("provider", "anthropic"))
    BULLET   = "•"

    def pick_key(field):
        v = body.get(field, "")
        return v if (v and BULLET not in str(v)) else cfg.get(field, "")

    try:
        if provider == "anthropic":
            key   = pick_key("anthropic_key")
            model = body.get("anthropic_model") or cfg.get("anthropic_model", "claude-opus-4-8")
            if not key:
                return jsonify({"ok": False, "error": "No Anthropic key provided"}), 400
            import anthropic as _ant
            client = _ant.Anthropic(api_key=key)
            resp = client.messages.create(model=model, max_tokens=20,
                                          messages=[{"role": "user", "content": "Say PONG"}])
            return jsonify({"ok": True, "reply": resp.content[0].text})
        elif provider == "openai":
            key   = pick_key("openai_key")
            model = body.get("openai_model") or cfg.get("openai_model", "gpt-4o")
            if not key:
                return jsonify({"ok": False, "error": "No OpenAI key provided"}), 400
            import openai as _oai
            client = _oai.OpenAI(api_key=key)
            resp = client.chat.completions.create(model=model, max_tokens=20,
                                                  messages=[{"role": "user", "content": "Say PONG"}])
            return jsonify({"ok": True, "reply": resp.choices[0].message.content})
        else:
            return jsonify({"ok": False, "error": "Unknown provider: {}".format(provider)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -- API: users ----------------------------------------------------------------

def _safe_user(u):
    return {k: v for k, v in u.items() if k != "password_hash"}

@app.route("/api/users", methods=["GET"])
def api_get_users():
    return jsonify([_safe_user(u) for u in get_db().get_users()])

@app.route("/api/users", methods=["POST"])
def api_create_user():
    body     = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    email    = (body.get("email") or "").strip()
    password = body.get("password") or ""
    role     = body.get("role", "viewer")
    if not username:
        return jsonify({"ok": False, "error": "Username required"}), 400
    if not password:
        return jsonify({"ok": False, "error": "Password required"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    db = get_db()
    if db.get_user_by_username(username):
        return jsonify({"ok": False, "error": "Username already exists"}), 400
    uid = db.create_user(username, email, role, hash_password(password))
    return jsonify({"ok": True, "id": uid})

@app.route("/api/users/<int:uid>", methods=["PUT"])
def api_update_user(uid):
    body = request.get_json(force=True)
    db   = get_db()
    user = db.get_user(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    fields = {}
    new_username = (body.get("username") or "").strip()
    if new_username and new_username != user["username"]:
        if db.get_user_by_username(new_username):
            return jsonify({"ok": False, "error": "Username already exists"}), 400
        fields["username"] = new_username
    if body.get("email") is not None:
        fields["email"] = body["email"].strip()
    if body.get("role") in ("admin", "analyst", "viewer"):
        fields["role"] = body["role"]
    if body.get("status") in ("active", "inactive"):
        fields["status"] = body["status"]
    if body.get("password"):
        fields["password_hash"] = hash_password(body["password"])
    db.update_user(uid, fields)
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>", methods=["DELETE"])
def api_delete_user(uid):
    db   = get_db()
    user = db.get_user(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user["role"] == "admin" and db.count_active_admins() <= 1:
        return jsonify({"ok": False, "error": "Cannot delete the last admin"}), 400
    db.delete_user(uid)
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>/set-default-admin", methods=["PATCH"])
def api_set_default_admin(uid):
    """Mark this user as the account auto-logged-in when every auth method is disabled.

    Exactly one user can hold the flag at a time — setting it here clears it from
    every other user in the same transaction (radio-button semantics, not a toggle).
    """
    db   = get_db()
    user = db.get_user(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if user["role"] != "admin" or user["status"] != "active":
        return jsonify({"ok": False, "error": "Default admin must be an active admin account"}), 400
    db.set_default_admin(uid)
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>/reset-password", methods=["POST"])
def api_reset_password(uid):
    body   = request.get_json(force=True)
    new_pw = body.get("password") or ""
    if not new_pw:
        return jsonify({"ok": False, "error": "Password required"}), 400
    db = get_db()
    if not db.get_user(uid):
        return jsonify({"ok": False, "error": "User not found"}), 404
    db.update_user(uid, {"password_hash": hash_password(new_pw)})
    return jsonify({"ok": True})

# -- API: restart --------------------------------------------------------------

@app.route("/api/restart", methods=["POST"])
def restart_server():
    def do_restart():
        time.sleep(0.8)
        os._exit(1)  # non-zero exit triggers systemd Restart=on-failure
    threading.Thread(target=do_restart, daemon=True).start()
    return jsonify({"ok": True})

# -- API: app logs -------------------------------------------------------------

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_LOG_LEVEL_NOS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}


@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    level   = (request.args.get("level") or "").upper()
    logger  = request.args.get("logger") or ""
    search  = request.args.get("search") or ""
    since   = request.args.get("since") or ""
    limit   = min(int(request.args.get("limit", 200)), 2000)
    offset  = max(int(request.args.get("offset", 0)), 0)

    conditions, params = [], []
    if level in _VALID_LOG_LEVELS:
        conditions.append("level_no >= ?")
        params.append(_LOG_LEVEL_NOS[level])
    if logger:
        conditions.append("logger LIKE ?")
        params.append(logger + "%")
    if search:
        conditions.append("message LIKE ?")
        params.append("%" + search + "%")
    if since:
        conditions.append("ts > ?")
        params.append(since)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    db = get_db()
    conn = db._conn()

    total = conn.execute(
        f"SELECT COUNT(*) FROM app_logs {where}", params
    ).fetchone()[0]

    rows = conn.execute(
        f"""SELECT id, ts, level, level_no, logger, message, exc_info
            FROM app_logs {where}
            ORDER BY id DESC LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ).fetchall()

    return jsonify({
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "records": [dict(r) for r in rows],
    })


@app.route("/api/logs/stats", methods=["GET"])
def api_get_log_stats():
    db   = get_db()
    conn = db._conn()

    by_level = {r["level"]: r["cnt"] for r in conn.execute(
        "SELECT level, COUNT(*) as cnt FROM app_logs GROUP BY level ORDER BY level_no DESC"
    ).fetchall()}
    loggers = [r[0] for r in conn.execute(
        "SELECT DISTINCT logger FROM app_logs ORDER BY logger"
    ).fetchall()]
    total = conn.execute("SELECT COUNT(*) FROM app_logs").fetchone()[0]
    row   = conn.execute("SELECT ts FROM app_logs ORDER BY id DESC LIMIT 1").fetchone()

    return jsonify({
        "total":     total,
        "by_level":  by_level,
        "loggers":   loggers,
        "latest_ts": row["ts"] if row else None,
    })


@app.route("/api/logs", methods=["DELETE"])
def api_clear_logs():
    db = get_db()
    with db._write_lock:
        db._conn().execute("DELETE FROM app_logs")
        db._conn().commit()
    log.info("App logs cleared")
    return jsonify({"status": "cleared"})


@app.route("/api/logs/level", methods=["POST"])
def api_set_log_level():
    level = (request.args.get("level") or "").upper()
    if level not in _VALID_LOG_LEVELS:
        return jsonify({"error": f"Invalid level '{level}'"}), 400
    global _log_handler
    if _log_handler is not None:
        _log_handler.set_capture_level(logging.getLevelName(level))
    else:
        logging.getLogger("pktpcap").setLevel(logging.getLevelName(level))
    log.info(f"Log capture level changed to {level}")
    return jsonify({"status": "ok", "level": level})


# -- API: screenshots ----------------------------------------------------------

@app.route("/api/save-image", methods=["POST"])
def save_image():
    import base64, re
    body      = request.get_json(force=True)
    filename  = body.get("filename", "screenshot.png")
    data_url  = body.get("dataUrl", "")
    filename  = re.sub(r"[^a-zA-Z0-9_\-.]", "_", filename)
    match     = re.match(r"data:image/\w+;base64,(.*)", data_url, re.DOTALL)
    if not match:
        return jsonify({"ok": False, "error": "Invalid data URL"}), 400
    img_bytes = base64.b64decode(match.group(1))
    out_dir   = BASE / "screenshots"
    out_dir.mkdir(exist_ok=True)
    (out_dir / filename).write_bytes(img_bytes)
    return jsonify({"ok": True, "path": str(out_dir / filename)})

@app.route("/api/screenshot", methods=["POST"])
def take_screenshot():
    import re, subprocess
    body     = request.get_json(force=True)
    filename = re.sub(r"[^a-zA-Z0-9_\-.]", "_", body.get("filename", "screenshot.png"))
    out_dir  = BASE / "screenshots"
    out_dir.mkdir(exist_ok=True)
    out_path = str(out_dir / filename).replace("\\", "/")
    ps = (
        r"Add-Type -AssemblyName System.Drawing" + "\n"
        r'Add-Type @"' + "\n"
        r"using System;" + "\n"
        r"using System.Drawing;" + "\n"
        r"using System.Runtime.InteropServices;" + "\n"
        r"public class Win32 {" + "\n"
        r"    [DllImport(""user32.dll"")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint nFlags);" + "\n"
        r"    [DllImport(""user32.dll"")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);" + "\n"
        r"    [StructLayout(LayoutKind.Sequential)]" + "\n"
        r"    public struct RECT { public int Left, Top, Right, Bottom; }" + "\n"
        r"}" + "\n"
        r'"@' + "\n"
        r'$chrome = Get-Process | Where-Object { $_.Name -eq "chrome" -and $_.MainWindowHandle -ne [IntPtr]::Zero } | Sort-Object CPU -Descending | Select-Object -First 1' + "\n"
        r'if (-not $chrome) { Write-Error "Chrome not found"; exit 1 }' + "\n"
        r"$hwnd = $chrome.MainWindowHandle" + "\n"
        r"$rect = New-Object Win32+RECT" + "\n"
        r"[Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null" + "\n"
        r"$w = $rect.Right - $rect.Left" + "\n"
        r"$h = $rect.Bottom - $rect.Top" + "\n"
        r"$bmp = New-Object System.Drawing.Bitmap($w, $h)" + "\n"
        r"$g = [System.Drawing.Graphics]::FromImage($bmp)" + "\n"
        r"$hdc = $g.GetHdc()" + "\n"
        r"[Win32]::PrintWindow($hwnd, $hdc, 2) | Out-Null" + "\n"
        r"$g.ReleaseHdc($hdc)" + "\n"
        + "$bmp.Save('" + out_path + "')\n"
        r"$bmp.Dispose(); $g.Dispose()"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        return jsonify({"ok": False, "error": result.stderr[:300]}), 500
    return jsonify({"ok": True, "path": out_path})

# -- API: Live Feeds -----------------------------------------------------------

_FEED_NAME_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")

@app.route("/api/feed/<name>", methods=["POST"])
def receive_feed(name):
    """Streaming endpoint -- tshark/Wireshark pushes raw pcapng bytes here."""
    if not _check_feed_auth():
        return jsonify({"error": "Unauthorized -- include Authorization: Bearer <token> header"}), 401
    if not _FEED_NAME_RE.match(name):
        return jsonify({"error": "Invalid session name (alphanumeric, hyphens, underscores; max 64 chars)"}), 400

    # Feeds named ws-<ip>-<time> come from the Wireshark SSH-remote-capture
    # wrapper (service/pktpcap), which already gates on wireshark_capture_enabled
    # before it ever runs dumpcap. Everything else is a direct tshark/CLI push,
    # gated here on tshark_capture_enabled.
    if not name.startswith("ws-") and not load_config().get("tshark_capture_enabled", True):
        return jsonify({"error": "tshark/CLI captures are currently disabled in pktPCAP Live Feeds settings"}), 403

    session = _get_or_create_feed(name, request.remote_addr or "unknown")
    with session._lock:
        session.connected = True

    try:
        stream = request.stream
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            session.append(chunk)
    finally:
        with session._lock:
            session.connected = False
        _save_feed_to_disk(session)

    return jsonify({"ok": True, "bytes_received": session.bytes_received})

@app.route("/api/net-interfaces", methods=["GET"])
def api_net_interfaces():
    """This server's own interfaces -- relevant to the Wireshark-GUI SSH remote
    capture tab, where tshark runs on this host, not the tshark/CLI tab's
    arbitrary remote host, which we have no way to introspect in advance."""
    return jsonify({"interfaces": _list_local_interfaces()})

@app.route("/api/feeds", methods=["GET"])
def list_feeds():
    with _feed_sessions_lock:
        result = [s.to_dict() for s in _feed_sessions.values()]
    result.sort(key=lambda s: (not s["connected"], -s["last_seen"]))
    return jsonify(result)

@app.route("/api/feeds/<name>/download", methods=["GET"])
def download_feed(name):
    with _feed_sessions_lock:
        session = _feed_sessions.get(name)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    data = session.get_bytes()
    if not data:
        return jsonify({"error": "No data captured yet"}), 404
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="{}.pcapng"'.format(name)},
    )

@app.route("/api/feeds/<name>", methods=["DELETE"])
def delete_feed(name):
    with _feed_sessions_lock:
        _feed_sessions.pop(name, None)
    return jsonify({"ok": True})

@app.route("/api/captures", methods=["GET"])
def list_captures():
    """Capture files persisted to storage_path -- these survive past the
    in-memory feed sessions (which are capped at 200MB and lost on restart)."""
    d = _captures_dir()
    if not d:
        return jsonify({"storage_path_configured": False, "captures": []})
    if not d.is_dir():
        return jsonify({"storage_path_configured": True, "captures": []})
    out = []
    for f in d.iterdir():
        if f.is_file() and _CAPTURE_FILE_RE.match(f.name):
            st = f.stat()
            out.append({"name": f.name, "size": st.st_size, "modified": st.st_mtime})
    out.sort(key=lambda c: -c["modified"])
    return jsonify({"storage_path_configured": True, "captures": out})

@app.route("/api/captures/<fname>/download", methods=["GET"])
def download_capture(fname):
    d = _captures_dir()
    if not d or not _CAPTURE_FILE_RE.match(fname):
        return jsonify({"error": "Not found"}), 404
    fpath = d / fname
    if not fpath.is_file():
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(d, fname, as_attachment=True, mimetype="application/octet-stream")

@app.route("/api/captures/<fname>", methods=["DELETE"])
def delete_capture(fname):
    d = _captures_dir()
    if not d or not _CAPTURE_FILE_RE.match(fname):
        return jsonify({"error": "Not found"}), 404
    fpath = d / fname
    try:
        fpath.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


# ── Suite token registration (called by pktHub after registration) ─────────────
@app.route("/api/suite/register", methods=["POST"])
def suite_register():
    """
    pktHub pushes the new suite token here on every registration/rotation.
    Writes directly to SQLite (the authoritative store for load_config()).
    """
    data = request.get_json(silent=True) or {}
    new_token = (data.get("suite_token") or "").strip()
    if not new_token:
        return jsonify({"error": "suite_token required"}), 400
    try:
        # Write directly to SQLite — bypasses any caching in load_config()
        import sqlite3 as _sq
        _db_path = str(load_db_config().get("db_path", "pktpcap.db"))
        if not os.path.isabs(_db_path):
            _db_path = str(BASE / _db_path)
        _conn = _sq.connect(_db_path)
        _conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('suite_token', ?)", (new_token,))
        _conn.commit()
        _conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
# ── End suite token registration ───────────────────────────────────────────────


@app.route("/api/suite/regenerate", methods=["POST"])
def regenerate_suite_token():
    """Generate a new suite token, revoking the old one."""
    import sqlite3 as _sq, secrets as _sec
    try:
        _db_path = load_db_config().get("db_path", "pktpcap.db")
        if not os.path.isabs(_db_path):
            _db_path = str(BASE / _db_path)
        _new = _sec.token_urlsafe(32)
        _conn = _sq.connect(_db_path)
        _conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('suite_token',?)", (_new,))
        _conn.commit()
        _conn.close()
        return jsonify({"suite_token": _new, "status": "regenerated"}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

# ── Suite token (pktHub integration) ─────────────────────────────────────────
@app.route("/api/suite/token", methods=["GET"])
def get_suite_token():
    """Return the current suite token for display in Settings UI."""
    cfg = load_config()
    token = (cfg.get("suite_token") or "").strip()
    return jsonify({"suite_token": token, "has_token": bool(token)})


@app.route("/api/suite/whoami", methods=["GET"])
def suite_whoami():
    """
    Authenticated identity check — NOT in _AUTH_PUBLIC, so require_login above
    already gated this on a valid session or X-Suite-Token before we get here.
    A sibling pkt* app's "Test Connection" button calls this (not the public
    /api/health) so a wrong/revoked token fails the test instead of silently
    reporting a healthy connection.
    """
    return jsonify({
        "authenticated": True,
        "app": "pktpcap",
        "role": session.get("role"),
    }), 200

# -- API: integrations (outbound — pktpcap as a suite-token CLIENT) ------------
# Named connections to sibling pkt* apps pktpcap could pull data from. No
# consumer feature reads from this table yet — it exists so a connection can
# be configured ahead of any future integration being wired up, same pattern
# pktIPAM/pktflow/pktWiFi use for their own sibling connections.

_INTEGRATION_APPS = ("pktipam", "pktflow", "pktsnmp", "pktlog", "pktwifi", "pkthub")


def _integration_out(r):
    return {
        "id": r["id"], "name": r["name"], "app_name": r["app_name"], "base_url": r["base_url"],
        "has_token": bool(r["suite_token"]), "enabled": bool(r["enabled"]),
        "health_status": r["health_status"], "last_health_check": r["last_health_check"],
    }


@app.route("/api/integrations", methods=["GET"])
def api_get_integrations():
    return jsonify([_integration_out(r) for r in get_db().get_integrations()])


@app.route("/api/integrations", methods=["POST"])
def api_create_integration():
    if session.get("role") != "admin":
        return jsonify({"ok": False, "error": "Admin access required"}), 403
    body        = request.get_json(force=True)
    name        = (body.get("name") or "").strip()
    app_name    = body.get("app_name") or ""
    base_url    = (body.get("base_url") or "").strip().rstrip("/")
    suite_token = body.get("suite_token") or ""
    enabled     = bool(body.get("enabled", True))
    if not name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    if app_name not in _INTEGRATION_APPS:
        return jsonify({"ok": False, "error": f"app_name must be one of {_INTEGRATION_APPS}"}), 400
    if not base_url or not suite_token:
        return jsonify({"ok": False, "error": "base_url and suite_token required"}), 400
    import sqlite3 as _sq_int
    try:
        iid = get_db().create_integration(name, app_name, base_url, suite_token, enabled)
    except _sq_int.IntegrityError:
        return jsonify({"ok": False, "error": f"An integration named '{name}' already exists"}), 409
    return jsonify(_integration_out(get_db().get_integration(iid))), 201


@app.route("/api/integrations/<int:iid>", methods=["PUT"])
def api_update_integration(iid):
    if session.get("role") != "admin":
        return jsonify({"ok": False, "error": "Admin access required"}), 403
    db = get_db()
    if not db.get_integration(iid):
        return jsonify({"ok": False, "error": "Integration not found"}), 404
    body   = request.get_json(force=True)
    fields = {}
    if body.get("name") is not None:
        fields["name"] = body["name"].strip()
    if body.get("base_url") is not None:
        fields["base_url"] = body["base_url"].strip().rstrip("/")
    if body.get("suite_token"):
        fields["suite_token"] = body["suite_token"]
    if body.get("enabled") is not None:
        fields["enabled"] = int(bool(body["enabled"]))
    import sqlite3 as _sq_int
    try:
        db.update_integration(iid, fields)
    except _sq_int.IntegrityError:
        return jsonify({"ok": False, "error": f"An integration named '{fields.get('name')}' already exists"}), 409
    return jsonify(_integration_out(db.get_integration(iid)))


@app.route("/api/integrations/<int:iid>", methods=["DELETE"])
def api_delete_integration(iid):
    if session.get("role") != "admin":
        return jsonify({"ok": False, "error": "Admin access required"}), 403
    get_db().delete_integration(iid)
    return "", 204


@app.route("/api/integrations/<int:iid>/test", methods=["POST"])
def api_test_integration(iid):
    if session.get("role") != "admin":
        return jsonify({"ok": False, "error": "Admin access required"}), 403
    db  = get_db()
    row = db.get_integration(iid)
    if not row or not row["base_url"]:
        return jsonify({"ok": False, "error": "Integration is not configured yet"}), 400
    from suite_client import SuiteClient
    client = SuiteClient(row["base_url"], row["suite_token"], suite_user="pktpcap", suite_role="admin")
    healthy, detail = client.health_check()
    db.update_integration(iid, {"health_status": "ok" if healthy else "error", "last_health_check": datetime.datetime.utcnow().isoformat()})
    return jsonify({"healthy": healthy, "detail": detail})

# -- Entry point ---------------------------------------------------------------

def open_browser(port, scheme="http"):
    time.sleep(1.2)
    webbrowser.open("{}://localhost:{}/".format(scheme, port))

if __name__ == "__main__":
    init_db()
    _ensure_secret_key()
    _ensure_feed_token()

    # -- Attach in-app log handler -----------------------------------------------
    from logging_handler import SQLiteLogHandler
    _db_path = load_db_config().get("db_path", "pktpcap.db")
    if not os.path.isabs(_db_path):
        _db_path = str(BASE / _db_path)
    _log_handler = SQLiteLogHandler(db_path=_db_path)
    _log_handler.attach_to_root_logger("")  # root logger — catches Flask, werkzeug, everything
    # ---------------------------------------------------------------------------

    cfg  = load_config()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else cfg.get("port", 8765)

    ssl_enabled = cfg.get("ssl_enabled", False)
    ssl_cert    = cfg.get("ssl_cert", "")
    ssl_key_    = cfg.get("ssl_key", "")
    ssl_context = None
    scheme      = "http"

    if ssl_enabled and ssl_cert and ssl_key_:
        if not os.path.isfile(ssl_cert):
            log.warning("SSL cert not found: %s", ssl_cert)
            print("  WARNING: SSL cert not found: {}".format(ssl_cert))
        elif not os.path.isfile(ssl_key_):
            log.warning("SSL key not found: %s", ssl_key_)
            print("  WARNING: SSL key not found: {}".format(ssl_key_))
        else:
            ssl_context = (ssl_cert, ssl_key_)
            scheme = "https"

    # Auto-detect SSL from ssl/ subdirectory (original behaviour — db ssl_enabled flag not required)
    if ssl_context is None:
        _auto_crt = BASE / "ssl" / "server.crt"
        _auto_key = BASE / "ssl" / "server.key"
        if _auto_crt.is_file() and _auto_key.is_file():
            ssl_context = (str(_auto_crt), str(_auto_key))
            scheme = "https"
            log.info("SSL auto-detected from ssl/ directory")

    log.info("pktPCAP starting on %s://0.0.0.0:%s", scheme, port)
    print("\n  pktPCAP")
    print("  " + "-" * 37)
    print("  App      ->  {}://localhost:{}/".format(scheme, port))
    print("  Settings ->  {}://localhost:{}/settings".format(scheme, port))
    print("  DB       ->  {}".format(load_db_config().get("db_path", "pktpcap.db")))
    print()

    if not os.environ.get("PKTPCAP_NO_BROWSER"):
        threading.Thread(target=open_browser, args=(port, scheme), daemon=True).start()
    backup_job.start_scheduler(load_config, _db_path)
    app.run(host="0.0.0.0", port=port, ssl_context=ssl_context, threaded=True)

