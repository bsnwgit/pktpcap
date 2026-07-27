#!/bin/bash
# pktPCAP install script — Ubuntu Server 22.04/24.04 LTS
# Usage: bash install.sh
# Prompts for the install directory (default /opt/pktpcap) and port (default
# 8765) when run interactively.
# Override defaults with env vars to skip the prompts, e.g.:
#   PKTPCAP_INSTALL_DIR=/opt/pktpcap PKTPCAP_SERVICE_USER=pktpcap PKTPCAP_PORT=8765 bash install.sh

set -euo pipefail

if [ -z "${PKTPCAP_INSTALL_DIR:-}" ] && [ -t 0 ]; then
    read -rp "Install directory [/opt/pktpcap]: " INSTALL_DIR_INPUT
    INSTALL_DIR="${INSTALL_DIR_INPUT:-/opt/pktpcap}"
else
    INSTALL_DIR="${PKTPCAP_INSTALL_DIR:-/opt/pktpcap}"
fi
if [ -z "${PKTPCAP_PORT:-}" ] && [ -t 0 ]; then
    read -rp "Port [8765]: " PORT_INPUT
    PORT="${PORT_INPUT:-8765}"
else
    PORT="${PKTPCAP_PORT:-8765}"
fi
LOG_DIR="${PKTPCAP_LOG_DIR:-$INSTALL_DIR/logs}"
SERVICE_USER="${PKTPCAP_SERVICE_USER:-$(whoami)}"
SERVICE_GROUP="${PKTPCAP_SERVICE_GROUP:-$SERVICE_USER}"
VENV="$INSTALL_DIR/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR"
LOCAL_IP="$(hostname -I | awk '{print $1}')"

echo "=== pktPCAP Installer ==="
echo "Install dir: $INSTALL_DIR"
echo "Service user: $SERVICE_USER"
echo "Port: $PORT"
echo ""

# -- 1. System packages --------------------------------------------------------
echo "[1/8] Installing system packages..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config gcc \
    curl ca-certificates

# -- 2. Create install + log directories ---------------------------------------
echo "[2/8] Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$LOG_DIR"
sudo mkdir -p "$INSTALL_DIR/ssl"
sudo mkdir -p "$INSTALL_DIR/captures"
# Owned by the invoking user for now so the steps below don't need sudo;
# re-owned to $SERVICE_USER:$SERVICE_GROUP at the end (step 8).
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$LOG_DIR"

# -- 3. Python virtualenv -------------------------------------------------------
echo "[3/8] Setting up Python virtualenv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
echo "  Python dependencies installed."

# -- 4. Copy application files --------------------------------------------------
echo "[4/8] Copying application files..."
if [ "$REPO_DIR" = "$INSTALL_DIR" ]; then
    echo "  Install dir is the repo checkout itself — nothing to copy."
else
    cp -r "$REPO_DIR/app"        "$INSTALL_DIR/"
    cp -r "$REPO_DIR/migrations" "$INSTALL_DIR/"
    cp -r "$REPO_DIR/icon.svg" "$REPO_DIR/lockup.svg" "$INSTALL_DIR/" 2>/dev/null || true
fi
# Wireshark SSH Remote Capture wrapper — installed at the top level of the
# install dir (matches the path Wireshark's own config points at:
# <install_dir>/pktpcap), with __PORT__ substituted.
cp "$REPO_DIR/scripts/pktpcap" "$INSTALL_DIR/pktpcap"
sed -i "s#__PORT__#$PORT#g" "$INSTALL_DIR/pktpcap"
chmod +x "$INSTALL_DIR/pktpcap"

# -- 5. Configure ----------------------------------------------------------------
echo "[5/8] Setting up config..."
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    cp "$REPO_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml"
    SECRET=$(openssl rand -hex 32)
    sed -i "s/CHANGE_ME_generate_with_openssl_rand_hex_32/$SECRET/" "$INSTALL_DIR/config.yaml"
    sed -i "s#http://SERVER-IP:8765#http://$LOCAL_IP:$PORT#g" "$INSTALL_DIR/config.yaml"
    sed -i "s/^port: 8765/port: $PORT/" "$INSTALL_DIR/config.yaml"
    # Pin install_dir explicitly (app/config.py derives every other path —
    # db, logs, ssl, captures, backups — from this by default).
    echo "install_dir: \"$INSTALL_DIR\"" >> "$INSTALL_DIR/config.yaml"
    echo "  Config created at $INSTALL_DIR/config.yaml"
    echo "  !! Review and update cors_origins before production use !!"
else
    echo "  Config already exists — skipping."
fi

# -- 6. Apply migrations + create admin user -----------------------------------
echo "[6/8] Initializing database and admin user..."
DB_EXISTED=0
[ -f "$INSTALL_DIR/pktpcap.db" ] && DB_EXISTED=1
ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

PKTPCAP_CONFIG="$INSTALL_DIR/config.yaml" \
PKTPCAP_INSTALL_DIR="$INSTALL_DIR" \
PKTPCAP_ADMIN_PASSWORD="$ADMIN_PASS" \
"$VENV/bin/python3" - << PYEOF
import asyncio, sys
sys.path.insert(0, '$INSTALL_DIR')

from app.database import init_db, seed_admin

async def setup():
    await init_db()
    await seed_admin()
    print("  Database initialized.")

asyncio.run(setup())
PYEOF

if [ "$DB_EXISTED" -eq 0 ]; then
    echo ""
    echo "==================================================================="
    echo " pktPCAP initial admin credentials — SAVE THESE, shown only once:"
    echo "   username: admin"
    echo "   password: ${ADMIN_PASS}"
    echo "==================================================================="
    echo ""
else
    echo "  Existing database found — admin account left untouched."
fi

# -- 7. Build frontend -----------------------------------------------------------
# Not installing Node.js itself here (version management is left to the
# operator), but if it's already present, just build it.
echo "[7/8] Building frontend..."
FRONTEND_BUILT=0
if command -v npm &>/dev/null; then
    ( cd "$REPO_DIR/frontend" && npm install --no-audit --no-fund && npm run build )
    mkdir -p "$INSTALL_DIR/frontend"
    if [ "$REPO_DIR/frontend/dist" != "$INSTALL_DIR/frontend/dist" ]; then
        rm -rf "$INSTALL_DIR/frontend/dist"
        cp -r "$REPO_DIR/frontend/dist" "$INSTALL_DIR/frontend/dist"
    fi
    FRONTEND_BUILT=1
    echo "  Frontend built and deployed."
else
    echo "  npm not found — skipping (Node.js is required)."
    echo "  The web UI will return \"Not Found\" until you build it manually — see the"
    echo "  banner at the end of this script for the exact commands."
fi

# -- 8. Install systemd service ----------------------------------------------------
echo "[8/8] Installing systemd service..."
# Re-own the install/log dirs to the service user before starting the service.
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" "$LOG_DIR"
sed \
    -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
    -e "s#__LOG_DIR__#$LOG_DIR#g" \
    -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
    -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
    "$REPO_DIR/pktpcap.service" | sudo tee /etc/systemd/system/pktpcap.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable pktpcap
sudo systemctl start pktpcap

# -- Open the firewall -------------------------------------------------------------
echo "Opening firewall (port $PORT/tcp)..."
if command -v ufw &>/dev/null; then
    sudo ufw allow "$PORT/tcp" || true
else
    echo "  ufw not found — open port $PORT/tcp manually if you have another firewall active."
fi

echo ""
echo "+----------------------------------------------------------+"
echo "|             pktPCAP installed successfully!               |"
echo "+----------------------------------------------------------+"
printf "|  URL:           http://%-35s|\n" "$LOCAL_IP:$PORT"
if [ "$DB_EXISTED" -eq 0 ]; then
    echo "|  Username:      admin                                    |"
    printf "|  Password:      %-43s|\n" "$ADMIN_PASS"
    echo "|                                                          |"
    echo "|  SAVE THESE CREDENTIALS — they won't be shown again!     |"
else
    echo "|  Existing install — admin credentials unchanged          |"
fi
echo "+----------------------------------------------------------+"
echo ""
if [ "$FRONTEND_BUILT" -eq 0 ]; then
    echo "!! Frontend was NOT built (npm not found) — the web UI will show"
    echo "!! {\"detail\":\"Not Found\"} until you run:"
    echo "!!   cd $REPO_DIR/frontend && npm install && npm run build"
    if [ "$REPO_DIR/frontend/dist" != "$INSTALL_DIR/frontend/dist" ]; then
        echo "!!   mkdir -p $INSTALL_DIR/frontend && cp -r $REPO_DIR/frontend/dist $INSTALL_DIR/frontend/dist"
    fi
    echo "!!   sudo systemctl restart pktpcap"
    echo ""
fi
echo "Next steps:"
echo "  1. Log in and change the admin password if needed"
echo "  2. Add an Anthropic or OpenAI API key in Settings -> Security -> AI Assistant (optional)"
echo "  3. Configure a Storage path in Settings -> Captures to persist live-fed captures to disk"
echo "  4. Check service status: sudo systemctl status pktpcap"
