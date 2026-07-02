#!/bin/sh
# pktPCAP container entrypoint
# Validates required env vars, bootstraps the database, then starts the app.
set -e

# ── Require APP_ADMIN_PASSWORD ────────────────────────────────────────────────
if [ -z "$APP_ADMIN_PASSWORD" ]; then
  echo ""
  echo "  ERROR ──────────────────────────────────────────────────────────────"
  echo "  APP_ADMIN_PASSWORD is required and must not be blank."
  echo "  Set it in your .env file before starting the container."
  echo "  ────────────────────────────────────────────────────────────────────"
  echo ""
  exit 1
fi

# ── Ensure data directories exist ────────────────────────────────────────────
mkdir -p /data /storage /app/ssl /app/screenshots

# ── Write config.json (points the app at the persistent data volume) ─────────
# Only written if not already present so a manually placed config is respected.
if [ ! -f /app/config.json ]; then
  echo '{"db_type":"sqlite","db_path":"/data/pktpcap.db"}' > /app/config.json
fi

# ── Bootstrap: seed admin user + sync port to DB ─────────────────────────────
python /app/docker_init.py

# ── Start pktPCAP ─────────────────────────────────────────────────────────────
echo ""
echo "  pktPCAP starting..."
echo ""
exec python /app/server.py
