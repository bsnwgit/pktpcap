# ── pktPCAP — Docker image ────────────────────────────────────────────────────
# Build:  docker build -t pktpcap .
# Run:    docker compose up -d   (see docker-compose.yml)

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/bsnwgit/pktpcap"
LABEL org.opencontainers.image.description="pktPCAP — browser-based PCAP analyzer with live feed and AI triage"
LABEL org.opencontainers.image.licenses="MIT"

# ── System deps for python3-saml (libxmlsec1) ─────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Install Python dependencies first (layer-cached until requirements change) ─
COPY service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application source ────────────────────────────────────────────────────
COPY service/ /app/

# ── Copy container init script ────────────────────────────────────────────────
COPY docker_init.py /app/docker_init.py

# ── Copy entrypoint ───────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Persistent mount points ───────────────────────────────────────────────────
# /data     — SQLite database and app config (named volume)
# /storage  — PCAP uploads, screenshots (named volume, survives image updates)
# /app/ssl  — TLS certificate and key (named volume or bind mount)
RUN mkdir -p /data /storage /app/ssl /app/screenshots

# ── Default exposed port (overridden by APP_PORT env var at runtime) ──────────
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
