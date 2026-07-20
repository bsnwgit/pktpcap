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

echo "=== pktPCAP Installer ==="
echo "Install dir: $INSTALL_DIR"
echo "Service user: $SERVICE_USER"
echo "Port: $PORT"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/7] Installing system packages..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config gcc

# ── 2. Create directories ─────────────────────────────────────────────────────
echo "[2/7] Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$LOG_DIR"
# Owned by the invoking user for now so the steps below don't need sudo;
# re-owned to $SERVICE_USER:$SERVICE_GROUP at the end (step 7).
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$LOG_DIR"

# ── 3. Python virtualenv + dependencies ───────────────────────────────────────
echo "[3/7] Setting up Python virtualenv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$SCRIPT_DIR/service/requirements.txt"
echo "  Python dependencies installed."

# ── 4. Copy application files ─────────────────────────────────────────────────
echo "[4/7] Copying application files..."
if [ "$SCRIPT_DIR/service" = "$INSTALL_DIR" ]; then
    echo "  Install dir is the service/ checkout itself — nothing to copy."
else
    cp -r "$SCRIPT_DIR/service/"* "$INSTALL_DIR/"
fi
mkdir -p "$INSTALL_DIR/ssl"
sed -i "s#__PORT__#$PORT#g" "$INSTALL_DIR/pktpcap"
chmod +x "$INSTALL_DIR/pktpcap"
echo "  Application files copied. Place server.crt + server.key in $INSTALL_DIR/ssl to enable HTTPS."

# ── 5. Initialize database + admin user ──────────────────────────────────────
echo "[5/7] Initializing database..."
DB_EXISTED=0
[ -f "$INSTALL_DIR/pktpcap.db" ] && DB_EXISTED=1

ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)
PKTPCAP_ADMIN_PASSWORD="$ADMIN_PASS" \
"$VENV/bin/python3" - << PYEOF
import sys
sys.path.insert(0, "$INSTALL_DIR")
from db import init_db, get_db
init_db()
if $DB_EXISTED == 0:
    get_db().set_setting("port", $PORT)
print("  Database initialized at $INSTALL_DIR/pktpcap.db")
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

# ── 6. Install systemd service ────────────────────────────────────────────────
echo "[6/7] Installing systemd service..."
# Re-own the install/log dirs to the service user before starting the service.
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" "$LOG_DIR"
sed \
    -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
    -e "s#__LOG_DIR__#$LOG_DIR#g" \
    -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
    -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
    "$SCRIPT_DIR/pktpcap.service" | sudo tee /etc/systemd/system/pktpcap.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable pktpcap
sudo systemctl start pktpcap

# ── 7. Open the firewall ──────────────────────────────────────────────────────
echo "[7/7] Opening firewall (port $PORT/tcp)..."
if command -v ufw &>/dev/null; then
    sudo ufw allow "$PORT/tcp" || true
else
    echo "  ufw not found — open port $PORT/tcp manually if you have another firewall active."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              pktPCAP installed successfully!              ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  URL:           http://%-35s║\n" "$(hostname -I | awk '{print $1}'):$PORT"
if [ "$DB_EXISTED" -eq 0 ]; then
    echo "║  Username:      admin                                     ║"
    printf "║  Password:      %-43s║\n" "$ADMIN_PASS"
    echo "║                                                          ║"
    echo "║  SAVE THESE CREDENTIALS — they won't be shown again!     ║"
else
    echo "║  Existing install — admin credentials unchanged           ║"
fi
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Log in and change the admin password if needed"
echo "  2. Add an Anthropic or OpenAI API key in Settings (optional — AI panel only)"
echo "  3. Check service status: sudo systemctl status pktpcap"
