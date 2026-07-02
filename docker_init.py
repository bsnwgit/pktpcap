#!/usr/bin/env python3
"""
docker_init.py — pktPCAP container bootstrap

Runs once per container start (before server.py). Responsibilities:
  1. Initialise the database schema (idempotent).
  2. Seed the admin user from env vars on first run (skipped if users exist).
  3. Sync APP_PORT and APP_STORAGE_PATH env vars → DB settings on every start.

Environment variables consumed:
  APP_ADMIN_USER      Admin username          (default: admin)
  APP_ADMIN_PASSWORD  Admin password          (REQUIRED — entrypoint validates)
  APP_ADMIN_EMAIL     Admin email             (optional)
  APP_PORT            Listening port          (default: 80)
  APP_STORAGE_PATH    PCAP storage path       (default: /storage)
"""
import os
import sys

sys.path.insert(0, "/app")

from db import init_db, get_db, hash_password  # noqa: E402

# ── Init schema ───────────────────────────────────────────────────────────────
init_db()
db = get_db()

# ── Sync runtime settings ─────────────────────────────────────────────────────
port         = int(os.environ.get("APP_PORT", 80))
storage_path = os.environ.get("APP_STORAGE_PATH", "/storage")

db.set_setting("port", str(port))
db.set_setting("storage_path", storage_path)
print(f"[init] Port set to {port}")
print(f"[init] Storage path set to {storage_path}")

# ── Seed admin user (first run only) ─────────────────────────────────────────
conn  = db._conn()
users = conn.execute("SELECT id FROM users LIMIT 1").fetchone()

if not users:
    admin_user  = os.environ.get("APP_ADMIN_USER", "admin")
    admin_pass  = os.environ.get("APP_ADMIN_PASSWORD", "")
    admin_email = os.environ.get("APP_ADMIN_EMAIL", "")

    pw_hash = hash_password(admin_pass)
    conn.execute(
        "INSERT INTO users (username, password_hash, role, email, active) VALUES (?,?,?,?,?)",
        (admin_user, pw_hash, "admin", admin_email, 1),
    )
    conn.commit()
    print(f"[init] Admin user '{admin_user}' created.")
else:
    print("[init] Users already exist — skipping admin seed.")
