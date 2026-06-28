#!/usr/bin/env python3
"""
pktPCAP -- standalone web service
Run: python server.py
"""

import json, logging, os, sys, webbrowser, threading, time, secrets, re as _re, socket
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template, Response

from db import init_db, get_db, load_db_config, save_db_config, hash_password, Database

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

# -- Flask app -----------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

def load_config():
    return get_db().get_all_settings()

def save_config(cfg):
    get_db().set_many_settings(cfg)

# -- Routes --------------------------------------------------------------------

@app.route("/")
def index():
    resp = send_from_directory(BASE / "static", "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp

@app.route("/settings")
def settings_page():
    cfg = load_config()
    return render_template("settings.html", app_name=cfg.get("app_name", "pktPCAP"))

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
        "wireshark_capture_enabled",
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
        import subprocess
        subprocess.Popen([sys.executable] + sys.argv)
        os._exit(0)
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

    return jsonify({"ok": True, "bytes_received": session.bytes_received})

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

# -- Entry point ---------------------------------------------------------------

def open_browser(port, scheme="http"):
    time.sleep(1.2)
    webbrowser.open("{}://localhost:{}/".format(scheme, port))

if __name__ == "__main__":
    init_db()
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

    log.info("pktPCAP starting on %s://0.0.0.0:%s", scheme, port)
    print("\n  pktPCAP")
    print("  " + "-" * 37)
    print("  App      ->  {}://localhost:{}/".format(scheme, port))
    print("  Settings ->  {}://localhost:{}/settings".format(scheme, port))
    print("  DB       ->  {}".format(load_db_config().get("db_path", "pktpcap.db")))
    print()

    threading.Thread(target=open_browser, args=(port, scheme), daemon=True).start()
    app.run(host="0.0.0.0", port=port, ssl_context=ssl_context, threaded=True)
