#!/bin/bash
# pktPCAP install script — Ubuntu Server 22.04/24.04 LTS
# Usage: bash install.sh
# Override defaults with env vars, e.g.:
#   PKTPCAP_INSTALL_DIR=/opt/pktpcap PKTPCAP_SERVICE_USER=pktpcap bash install.sh

set -euo pipefail

INSTALL_DIR="${PKTPCAP_INSTALL_DIR:-/opt/pktpcap}"
LOG_DIR="${PKTPCAP_LOG_DIR:-$INSTALL_DIR/logs}"
SERVICE_USER="${PKTPCAP_SERVICE_USER:-$(whoami)}"
SERVICE_GROUP="${PKTPCAP_SERVICE_GROUP:-$SERVICE_USER}"
VENV="$INSTALL_DIR/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== pktPCAP Installer ==="
echo "Install dir: $INSTALL_DIR"
echo "Service user: $SERVICE_USER"
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
cp -r "$SCRIPT_DIR/service/"* "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/ssl"
echo "  Application files copied. Place server.crt + server.key in $INSTALL_DIR/ssl to enable HTTPS."

# ── 5. Initialize database + admin user ──────────────────────────────────────
echo "[5/7] Initializing database..."
"$VENV/bin/python3" - << PYEOF
import sys
sys.path.insert(0, "$INSTALL_DIR")
from db import init_db
init_db()
print("  Database initialized at $INSTALL_DIR/pktpcap.db")
PYEOF

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
echo "[7/7] Opening firewall (port 80/tcp)..."
if command -v ufw &>/dev/null; then
    sudo ufw allow 80/tcp || true
else
    echo "  ufw not found — open port 80/tcp manually if you have another firewall active."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              pktPCAP installed successfully!              ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  URL:           http://%-35s║\n" "$(hostname -I | awk '{print $1}'):80"
echo "║  Username:      admin                                     ║"
echo "║  Password:      admin  (CHANGE THIS IMMEDIATELY)          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Log in and change the default admin password"
echo "  2. Add an Anthropic or OpenAI API key in Settings (optional — AI panel only)"
echo "  3. Check service status: sudo systemctl status pktpcap"
