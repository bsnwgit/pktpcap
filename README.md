# pktPCAP

<p align="center">
  <img src="lockup-256h.png" alt="pktPCAP" height="64">
</p>

<p align="center">
  A standalone Python/Flask web service for analyzing PCAP files in the browser, with AI-powered triage and a live NetFlow feed.
</p>

---

## Overview

pktPCAP is a locally-hosted packet capture analyzer. Drop a `.pcap` or `.pcapng` file onto the UI and get instant, rule-based analysis of TCP health, DNS, threats, and traffic flows — no cloud upload required. Optional AI analysis (Anthropic or OpenAI) layers natural-language findings on top of the parsed data.

**Key traits:**
- Runs entirely on your infrastructure — captures never leave your environment
- Works without an API key (rule-based analysis only)
- Three analysis modes: Specific Issue, Auto-Triage, Security Review
- In-app log viewer, user management, Okta SAML SSO, SSL support, and a live pcapng feed endpoint (generic tshark/curl **or** native Wireshark GUI remote capture)
- Multi-channel alert notifications (Slack, Email, PagerDuty, generic webhook, Tracecat) and scheduled/on-demand backups
- Deploys as a systemd service on Ubuntu Server bare metal — no container runtime required

---

## Recent Changes (2026-07)

- **Docker removed.** The Dockerfile, `docker-compose.yml`, entrypoint script, CI workflow, and `.env.example` are gone. Deployment is now native: `install.sh` sets up a Python venv and a systemd unit directly on Ubuntu Server 22.04/24.04 bare metal — no container runtime needed.
- **Install script rebuilt.** `install.sh` is now fully interactive — it prompts for the install directory and port (with defaults), generates a random admin password and prints it once, and installs + starts the systemd service automatically, including opening the firewall port via `ufw` if present.
- **Default port changed from `80` to `8765`.** No more binding to a privileged port by default; the systemd unit only grants `CAP_NET_BIND_SERVICE` in case an admin explicitly sets a port below 1024.
- **Remote-capture script renamed** from the old `pkt-capture` name to `pktpcap` (installed at `<install_dir>/pktpcap`). It's the wrapper Wireshark's SSH Remote Capture feature invokes on the server; see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh).
- **Infra leakage sanitized.** Personal deploy scripts, hardcoded server IPs/SSH key paths/usernames, and a committed `PROJECT_CONTEXT.md` were removed from the repo; the remaining helper scripts take host/path values as CLI args or env vars.
- **Login form now submits on Enter** in either the username or password field — no need to click into the button.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/bsnwgit/pktpcap.git
cd pktpcap

# 2. Run the installer (do NOT prefix with sudo — it calls sudo itself
#    where needed). Run it as a normal, non-root user:
bash install.sh
```

`install.sh` is interactive when run from a terminal. It will:

1. Prompt for the **install directory** (default `/opt/pktpcap`)
2. Prompt for the **port** (default `8765`)
3. Install system packages, create a Python venv, and install dependencies
4. Copy the application into the install directory
5. Initialize the SQLite database and create the `admin` account with a **random password**, printed once to the terminal — save it, it is never shown again
6. Install, enable, and start the `pktpcap` systemd service
7. Open the port in `ufw` automatically, if `ufw` is installed (otherwise it prints a reminder to open it manually)

At the end it prints a boxed summary with the URL and admin credentials (on a fresh install only — an existing database is left untouched and the box says so instead).

Open `http://<server-ip>:<port>` (default port `8765`) and log in with the `admin` username and the generated password from the install output.

**Non-interactive / scripted installs** — set env vars to skip every prompt:

```bash
PKTPCAP_INSTALL_DIR=/opt/pktpcap PKTPCAP_PORT=8765 \
PKTPCAP_SERVICE_USER=pktpcap PKTPCAP_SERVICE_GROUP=pktpcap \
bash install.sh
```

### Environment variables

`install.sh` reads these to customize the install location, port, and service identity. The install-directory and port **prompts only appear when running interactively from a terminal** with the variable unset; setting the variable, or running the script non-interactively (piped input, cron, CI), skips the prompt and uses the variable's value (or the default) directly:

| Variable | Default | Description |
|---|---|---|
| `PKTPCAP_INSTALL_DIR` | `/opt/pktpcap` | Where the app is installed |
| `PKTPCAP_PORT` | `8765` | Listening port; also written into the `pktpcap` remote-capture wrapper and opened in `ufw` |
| `PKTPCAP_LOG_DIR` | `$PKTPCAP_INSTALL_DIR/logs` | systemd journal file location |
| `PKTPCAP_SERVICE_USER` | current user | User the systemd service runs as |
| `PKTPCAP_SERVICE_GROUP` | same as service user | Group the systemd service runs as |
| `PKTPCAP_ADMIN_PASSWORD` | (not read by `install.sh`) | `install.sh` always generates its own random password and ignores this variable if set. It's only honored by a **manual** `init_db()` call (see [Installation](#installation) step 6) — useful if you're bootstrapping the database yourself outside the installer |

---

## Installation

`install.sh` (see [Quick Start](#quick-start)) automates every step below, including opening the firewall (if `ufw` is present). This section is the full manual walkthrough — useful to customize the install, run steps individually, or understand what the script does.

### 1. Clone the repository

```bash
git clone https://github.com/bsnwgit/pktpcap.git
cd pktpcap
```

All commands below assume you're in the repo root unless otherwise noted.

### 2. Create the install directory

```bash
INSTALL_DIR=/opt/pktpcap
sudo mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/logs"
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$INSTALL_DIR/logs"
```

`/opt` is root-owned by default, so this needs `sudo`. Steps 3–5 below run as your regular user against this now-owned directory; step 6 re-owns everything to whichever user/group the systemd service runs as.

### 3. System packages

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config gcc
```

`libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config`, and `gcc` are required to build `python3-saml`'s xmlsec native bindings (used for Okta SAML SSO).

### 4. Install Python dependencies

```bash
python3 -m venv /opt/pktpcap/venv
/opt/pktpcap/venv/bin/pip install -r service/requirements.txt
```

### 5. Copy application files

```bash
cp -r service/* /opt/pktpcap/
mkdir -p /opt/pktpcap/ssl
```

The `ssl/` directory is where you place `server.crt` + `server.key` if you want HTTPS (see [SSL / TLS](#ssl--tls) below) — pktPCAP auto-detects them at startup.

### 6. Configure

Nothing is required — settings live in a SQLite database (`pktpcap.db`) that's created automatically on first start, seeded with sensible defaults (including a default port of `8765`) and an `admin` account. To pre-initialize it (so you can confirm it worked before starting the service) with a real password instead of the `admin`/`admin` fallback:

```bash
cd /opt/pktpcap
PKTPCAP_ADMIN_PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)" \
/opt/pktpcap/venv/bin/python3 -c "from db import init_db; init_db()"
```

All configuration afterward (API keys, port, storage, SSL, SSO, etc.) is done through the **Settings** UI once you've logged in — see [Application Settings](#configuration).

### 7. Install the systemd service

`pktpcap.service` is a template — substitute the placeholders before installing it, or just run `install.sh` which does this for you:

```bash
sed \
    -e "s#__INSTALL_DIR__#/opt/pktpcap#g" \
    -e "s#__LOG_DIR__#/opt/pktpcap/logs#g" \
    -e "s#__SERVICE_USER__#$(whoami)#g" \
    -e "s#__SERVICE_GROUP__#$(whoami)#g" \
    pktpcap.service | sudo tee /etc/systemd/system/pktpcap.service
sudo systemctl daemon-reload
sudo systemctl enable --now pktpcap
sudo systemctl status pktpcap
```

The unit grants `CAP_NET_BIND_SERVICE` in case you set Port below 1024 in Settings — the default (`8765`) doesn't need it.

### 8. Open the firewall

```bash
sudo ufw allow 8765/tcp
```

### 9. Verify

```bash
curl -s http://localhost/api/health
```

Log in at `http://<server-ip>:8765` with `admin` and either the password you set in step 6's `PKTPCAP_ADMIN_PASSWORD`, or `admin` if you skipped it (the `admin`/`admin` fallback only applies to this manual path — `install.sh` never leaves it in place, it always generates a random password). Change the password immediately in **Settings → Security → Users** if you used the fallback.

---

## Data Flow

pktPCAP supports two capture delivery modes: **local file upload** and **remote live capture**. Both paths ultimately produce a pcapng byte stream that the browser parses and analyzes.

---

### Mode 1 — Local File Analysis

The simplest path. You already have a capture file.

```
┌──────────────────────────────────────────────────────────────────┐
│  Your Machine                                                    │
│                                                                  │
│  [.pcap / .pcapng file]                                          │
│         │                                                        │
│         ▼ drag-and-drop / file picker                            │
│  [Browser — index.html]                                          │
│         │                                                        │
│         ├─ parsePcap() ──► JS packet parser (pure client-side)   │
│         │                  builds flows, TCP stats, DNS, threats  │
│         │                                                        │
│         ├─ Rule engine ──► anomaly detection (no server needed)  │
│         │                                                        │
│         └─ POST /api/ai ─► [pktPCAP Flask server]                │
│                                  │                               │
│                                  ▼                               │
│                     [Anthropic / OpenAI API]  (optional)         │
│                                  │                               │
│                                  ▼                               │
│                         AI findings panel                        │
└──────────────────────────────────────────────────────────────────┘
```

**What happens step by step:**

1. User drops a `.pcap` or `.pcapng` file on the browser UI.
2. The browser reads the file entirely client-side — bytes never leave the machine via the network.
3. `parsePcap()` in `index.html` walks every packet record and builds in-memory data structures: flow tuples, TCP flag counters, DNS query tables, and threat indicators.
4. Rule-based analysis runs immediately in the browser — no server round-trip needed.
5. If an AI key is configured, the browser POSTs the parsed summary to `/api/ai`. The Flask server proxies the request to Anthropic or OpenAI and returns the model's response.
6. Results are rendered across seven analysis tabs.

**Server role in local mode:** the Flask server is only involved for the AI proxy (`/api/ai`) and serving static files. Packet parsing is entirely client-side.

---

### Mode 2 — Remote Live Capture (Live Feed)

Use this when you want to capture traffic on a remote host and analyze it without physically moving a file.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Remote Capture Host                                                         │
│                                                                              │
│  NIC / tap ──► [tshark]                                                      │
│                  │  raw pcapng bytes on stdout                               │
│                  │  (-w - flag writes to stdout instead of a file)           │
│                  ▼                                                           │
│               [curl]                                                         │
│                  │  HTTP POST, chunked transfer encoding                     │
│                  │  Authorization: Bearer <feed-token>                       │
│                  │  Content-Type: application/octet-stream                   │
└──────────────────┼───────────────────────────────────────────────────────────┘
                   │  (network — LAN or VPN tunnel)
                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  pktPCAP Host                                                                │
│                                                                              │
│  POST /api/feed/<session-name>                                               │
│         │                                                                    │
│         ├─ Bearer token validated against feed_token in DB                   │
│         │                                                                    │
│         ├─ FeedSession.append() ─► in-memory ring buffer (200 MB cap)        │
│         │   (thread-safe, chunked 64 KB reads from request.stream)           │
│         │                                                                    │
│         └─ Session stays "connected" until curl closes the connection        │
│                                                                              │
│  GET /api/feeds                 ─► list active sessions + bytes buffered     │
│  GET /api/feeds/<name>/download ─► download buffered pcapng as a file        │
│  DELETE /api/feeds/<name>       ─► clear and remove session                  │
│                                                                              │
│  [User loads buffered capture in UI] ──► same parse/analysis path as Mode 1 │
└──────────────────────────────────────────────────────────────────────────────┘
```

**What happens step by step:**

1. User retrieves the feed token from **Settings → Live Feed Token**.
2. On the remote capture host, `tshark` captures packets on the chosen interface and writes raw pcapng to stdout.
3. The output is piped to `curl`, which streams it as an HTTP POST to the pktPCAP feed endpoint.
4. pktPCAP validates the Bearer token and appends incoming chunks to a named `FeedSession` buffer (up to 200 MB; bytes beyond the cap are silently dropped and `truncated` is flagged).
5. While the feed is active, `GET /api/feeds` shows session status and byte count.
6. When capture is complete (or at any point), the user clicks **Load from Feed** in the UI, which fetches the buffered bytes and runs the same client-side parse/analysis as Mode 1.
7. The session can be cleared with `DELETE /api/feeds/<name>` to free memory.

---

### Remote Collector — Software & Configuration

The remote capture host needs only two tools: **tshark** and **curl**. Both are available on Linux, macOS, and Windows.

#### tshark

tshark is the command-line interface to Wireshark. It handles raw packet capture, decoding, and pcapng output.

| Package | Install |
|---|---|
| Debian / Ubuntu | `sudo apt install tshark` |
| RHEL / CentOS | `sudo yum install wireshark-cli` |
| macOS (Homebrew) | `brew install wireshark` |
| Windows | Wireshark installer includes tshark |

**Key flags used in the feed pipeline:**

| Flag | Purpose |
|---|---|
| `-i <interface>` | Network interface to capture on (e.g., `eth0`, `en0`) |
| `-w -` | Write pcapng output to stdout instead of a file |
| `-f "<filter>"` | BPF capture filter — limits what gets captured |
| `-s <bytes>` | Snap length — truncates packets to N bytes (reduce bandwidth) |

**Listing available interfaces:**
```bash
tshark -D
```

#### curl

curl handles the HTTP transport to pktPCAP. The `--data-binary @-` flag tells curl to read the POST body from stdin, enabling the pipe.

#### Feed command (generic template)

```bash
tshark -i <interface> -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"
```

Replace:
- `<interface>` — capture interface name (see `tshark -D`)
- `<feed-token>` — token from **Settings → Capture Ingest** (see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh) below for where this lives in the UI)
- `<pktpcap-host>` — hostname or IP of the machine running pktPCAP
- `<session-name>` — alphanumeric label for this capture session

**With a BPF filter (capture only HTTP and DNS):**
```bash
tshark -i <interface> -f "port 80 or port 443 or port 53" -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"
```

**With snap length (first 256 bytes of each packet — reduces bandwidth):**
```bash
tshark -i <interface> -s 256 -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"
```

**HTTPS (if pktPCAP has SSL enabled):**
```bash
tshark -i <interface> -w - | curl -s -k \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "https://<pktpcap-host>/api/feed/<session-name>"
```

(`-k` skips cert verification for self-signed certs; use `--cacert <cert.pem>` for proper validation.)

#### Running as a background service (Linux systemd)

To run the feed continuously and restart automatically:

**`/etc/systemd/system/pktpcap-feed.service`:**
```ini
[Unit]
Description=pktPCAP Live Feed — <interface>
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'tshark -i <interface> -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"'
Restart=on-failure
RestartSec=5s
User=<capture-user>

[Install]
WantedBy=multi-user.target
```

> **Note:** on Linux, tshark requires either `root` or a user in the `wireshark` group with `dumpcap` setuid permissions. Run `sudo dpkg-reconfigure wireshark-common` (Debian/Ubuntu) or `sudo usermod -aG wireshark <user>` and log out/in.

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable pktpcap-feed
sudo systemctl start pktpcap-feed
sudo systemctl status pktpcap-feed
```

---

### Wireshark GUI Remote Capture (SSH)

Besides the generic tshark/curl pipe above, pktPCAP also supports feeding a **live Wireshark GUI session** directly, using Wireshark's built-in **SSH Remote Capture** interface type — no separate script to babysit, and you get a live packet view in Wireshark itself while pktPCAP simultaneously buffers the same stream.

This is powered by a small wrapper script, **`pktpcap`** (renamed from the old `pkt-capture`), installed at `<install_dir>/pktpcap` by `install.sh`. Wireshark SSHs into the pktPCAP host and runs this wrapper instead of `dumpcap` directly; the wrapper tees the capture — one copy goes to Wireshark over the SSH pipe, the other is POSTed to pktPCAP's own `/api/feed/<name>` endpoint, using the same buffered-session mechanism as the tshark method.

**Enable it:** Settings → **Capture Ingest** → toggle **Wireshark remote capture** on. Enabling it reveals the feed endpoint URL, the bearer token, and a pre-filled `pktpcap` command — copy these into Wireshark's capture options.

**In Wireshark:** Capture → Options → **+ (Manage Interfaces)** → **Remote Interfaces**, or the SSH remote capture interface type, then set:

| Field | Value |
|---|---|
| SSH Host | pktPCAP server IP |
| SSH User | a user with permission to run `dumpcap` (see the group note below) |
| Auth | key file, or password |
| Remote Capture Command | `<install_dir>/pktpcap` (default `/opt/pktpcap/pktpcap`) |
| Interface | the interface name on the pktPCAP host, e.g. `eth0` |

The wrapper itself checks whether Wireshark remote capture is enabled in Settings before running (`GET /api/settings` → `wireshark_capture_enabled`) and exits with an error if it's off, so leaving Wireshark configured but the toggle disabled fails safely rather than silently.

> **Note:** on the pktPCAP host, running `dumpcap` over SSH still needs either `root` or a user in the `wireshark` group with `dumpcap` setuid permissions — same requirement as the generic tshark method above (`sudo usermod -aG wireshark <ssh-user>`, then log out/in).

Once a live Wireshark session is running, its captured bytes are also visible from the pktPCAP UI as a normal Live Feed session (see [Live feed (remote capture)](#live-feed-remote-capture) below) — click **Load from Feed** to pull them in for the same rule-based/AI analysis as an uploaded file.

---

### Feed Session Lifecycle

```
tshark starts → POST /api/feed/<name> opens → session.connected = True
                                                    │
                               data flows in chunks (64 KB reads)
                                                    │
tshark stops → curl closes connection → session.connected = False
                                                    │
                               buffer persists in memory until:
                               - user loads it in the UI
                               - DELETE /api/feeds/<name>
                               - server restart
```

Buffer limit is **200 MB per named session**. If the stream exceeds this, the session's `truncated` flag is set and additional bytes are discarded. Monitor usage via `GET /api/feeds`.

---

## Features

| Feature | Description |
|---|---|
| File analysis | Parse `.pcap` / `.pcapng` / `.cap` up to 500 MB (configurable); drop multiple files to merge & correlate |
| Seven analysis tabs | Summary, Anomalies, Flows, TCP, UDP, DNS, Threats |
| AI assistant | Anthropic Claude or OpenAI GPT — proxied through the local server |
| Three analysis modes | Specific Issue · Auto-Triage · Security Review |
| Live feed — tshark/curl | Any remote host with `tshark` streams pcapng directly to the server over HTTP |
| Live feed — Wireshark GUI | Native Wireshark SSH Remote Capture support via the bundled `pktpcap` wrapper script — see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh) |
| In-app log viewer | SQLite ring-buffer of app logs, queryable from the Logs page; live log-level change from the UI |
| User management | Create/edit/delete local users with password reset; designate a default admin |
| Role-based access | `admin`, `analyst`, `viewer` — Settings and log clear require admin |
| SAML SSO | Okta integration via `python3-saml`, with auto-provisioning and role-sync from Okta attributes on login |
| Alert notifications | Slack, Email (SMTP), PagerDuty, generic Webhook, and Tracecat — each independently enabled with a built-in test-send button |
| Scheduled + on-demand backups | Snapshots the SQLite DB, `config.json`, and optionally capture storage on an interval, with rotation; "Run Backup Now" and a snapshot browser in Settings |
| SSL/HTTPS | Auto-detected from `ssl/` directory; custom cert path configurable in Settings |
| Settings UI | Web UI at `/settings` — no config file editing needed |
| Deployment | systemd service on Ubuntu Server 22.04/24.04 LTS (bare metal); no container runtime required |
| pktHub / Suite integration | Suite-token header auth for embedding in the pktHub dashboard suite; token lives in Settings → Security → Suite Integration |

---

## Requirements

- Python 3.10+
- pip packages: see `service/requirements.txt`
- System packages (for SAML): `libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config`, `gcc` (installed by `install.sh`)

---

## Configuration

All settings are stored in a SQLite database (`pktpcap.db`). A minimal `config.json` in `service/` tells the server which database to use — it is never committed.

**`config.json` schema:**

```json
{
  "db_type": "sqlite",
  "db_path": "pktpcap.db"
}
```

All settings below live in the SQLite `settings` table and are managed entirely through the web UI at `/settings` — organized into tabs that match the sections below. There is no settings file to hand-edit.

### General

| Key | Default | Description |
|---|---|---|
| `app_name` | `pktPCAP` | Displayed in the browser tab and header |
| `port` | `8765` | Listening port — **restart required** after changing (Settings → General → **Restart Service**) |
| `timezone` | `UTC` | Affects display of timestamps in the UI |

### Captures (Data → Storage)

| Key | Default | Description |
|---|---|---|
| `storage_path` | — | Directory where capture files are stored |
| `max_upload_mb` | `500` | Maximum size per uploaded capture file |
| `storage_quota_gb` | `50` | Total disk quota for all captures |
| `retention_days` | `90` | Delete captures older than this |
| `auto_purge` | `false` | Automatically enforce the retention period |

### Database (Data → Storage)

| Key | Default | Description |
|---|---|---|
| `db_path` | `pktpcap.db` | SQLite file path — **Test** validates it opens, **Apply** switches to it (restart required) |

### Backups (Data → Backups)

| Key | Default | Description |
|---|---|---|
| `auto_backup` | `false` | Enable the scheduled background backup thread |
| `backup_path` | — | Directory snapshots are written to (falls back to `service/backups/` if unset) |
| `backup_interval_hours` | `24` | How often the scheduler runs while `auto_backup` is on |
| `backup_rotation` | `7` | Number of snapshot directories to keep before pruning the oldest |
| `backup_include_captures` | `false` | Also copy `storage_path` into each snapshot (can be large) |

Each snapshot is a `backup_<timestamp>/` directory containing `pktpcap.db`, `config.json`, and (if enabled) a `captures/` copy. **Run Backup Now** in Settings triggers one immediately; the **Snapshots** table below it lists existing backups with size and file contents. This is the *in-app* backup feature (`service/backup_job.py`) — distinct from the standalone `backup.py` at the repo root, which is a 2-rotation checkout snapshotter for developers (see [Project Structure](#project-structure)).

### Notifications

Each channel below has its own enable toggle and a **Test** button (`POST /api/notifications/test`) that sends a real test message using the saved settings.

| Key | Default | Description |
|---|---|---|
| `notify_slack_enabled` / `notify_slack_webhook_url` / `notify_slack_channel` | `false` / — / — | Slack incoming webhook |
| `notify_email_enabled` / `notify_email_smtp_host` / `notify_email_smtp_port` / `notify_smtp_tls` / `notify_email_username` / `notify_email_password` / `notify_email_from` / `notify_email_default_to` | `false` / — / `587` / `true` / — / — / — / — | SMTP email (supports STARTTLS + auth) |
| `notify_pagerduty_enabled` / `notify_pagerduty_integration_key` | `false` / — | PagerDuty Events API v2 |
| `notify_webhook_enabled` / `notify_webhook_url` / `notify_webhook_method` / `notify_webhook_payload_template` | `false` / — / `POST` / `{"text":"{{message}}"}` | Generic JSON webhook; template supports `{{message}}`, `{{alert_name}}`, `{{severity}}`, `{{fired_at}}` |
| `notify_tracecat_enabled` / `notify_tracecat_webhook_url` / `notify_tracecat_api_token` | `false` / — / — | Tracecat webhook integration |

### Security → Users / Auth

| Key | Default | Description |
|---|---|---|
| `local_auth_enabled` | `true` | Username/password login using local accounts; disabling hides local login fields (SSO-only) |
| `session_timeout_minutes` | `480` | Session idle timeout |
| `okta_saml_enabled` | `false` | Enable Okta SAML 2.0 SSO |
| `okta_metadata_xml` | — | Paste Okta's IdP metadata XML here — auto-fills entity ID, SSO URL, and cert below |
| `okta_entity_id` / `okta_sso_url` / `okta_cert` | — | IdP Entity ID, SSO URL, and X.509 cert (auto-filled from metadata XML, or set individually) |
| `okta_sp_entity_id` | (auto) | Optional custom SP Entity ID; the ACS URL and SP metadata (`/api/auth/saml/metadata`) are read-only/generated |
| `okta_sp_cert` / `okta_sp_key` | — | Optional SP certificate/key, for signed authentication requests |

SAML users are **auto-provisioned** on first login (Okta access is treated as trusted) and their role is **synced from Okta attributes** (`role`, `Role`, `userRole`, `pktpcap_role`, or `appRole`) on every subsequent login if Okta sends one — otherwise the role set at provisioning time is left alone.

### Security → Suite Integration

The Suite Token (Settings → Security → **Suite Integration**) is what pktHub (or another suite app) uses to authenticate as a forwarded user via the `X-Suite-Token` / `X-Suite-User` / `X-Suite-Role` headers — no separate login flow needed when embedded. Reveal/copy it from Settings and paste it into pktHub's App Registration; **Regen** invalidates the old token immediately (re-register in pktHub afterward).

### Security → AI Assistant

| Key | Default | Description |
|---|---|---|
| `provider` | `anthropic` | AI provider (`anthropic` or `openai`) |
| `anthropic_key` | — | Anthropic API key — **Test** sends a "Say PONG" round-trip |
| `anthropic_model` | `claude-opus-4-8` | Also selectable: `claude-sonnet-5`, `claude-haiku-4-5-20251001` |
| `openai_key` | — | OpenAI API key — **Test** sends a "Say PONG" round-trip |
| `openai_model` | `gpt-4o` | Also selectable: `gpt-4o-mini`, `o1`, or any model name typed manually |

### Security → SSL/TLS

| Key | Default | Description |
|---|---|---|
| `ssl_enabled` | `false` | Enable HTTPS — **file presence in `ssl/` is authoritative for auto-detection regardless of this flag** (see [SSL / TLS](#ssl--tls)) |
| `ssl_cert` / `ssl_key` | — | Cert/key paths (overridden by `ssl/server.crt` + `ssl/server.key` if present) |
| `pfx_mode` / `pfx_path` / `pfx_passphrase` | — | Optional PFX/PKCS#12 cert upload path, converted server-side |
| `pem_cert_path` / `pem_key_path` | — | Optional PEM cert/key path pair as an alternative to the `ssl/` directory |

### User Keys

| Key | Default | Description |
|---|---|---|
| `lucid_api_token` | — | Used for diagram export to Lucidchart |

### Capture Ingest

| Key | Default | Description |
|---|---|---|
| `wireshark_capture_enabled` | `false` | Accept live feeds from the `pktpcap` remote-capture wrapper / Wireshark SSH Remote Capture — see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh) |
| `feed_token` | (auto-generated) | Bearer token required on every `POST /api/feed/<name>` request — shown (with Copy/Rotate) in this tab once Wireshark capture is enabled; also usable with the generic tshark/curl method |

---

## Usage

### Analyzing a capture file

1. Open the app in your browser and log in (the login form submits on Enter from either field, no need to click Sign In)
2. Drag-and-drop a `.pcap`, `.pcapng`, or `.cap` file onto the upload zone, or click to browse — drop multiple files to merge & correlate them
3. Choose an analysis mode:
   - **Specific Issue** — describe a known problem; AI focuses on it
   - **Auto-Triage** — AI scans for anything suspicious
   - **Security Review** — security-focused analysis
4. Click **Run Auto-Triage** (or **Analyze Captures** for specific issue mode)
5. Results appear across seven tabs — scroll with the `‹` / `›` arrows if not all are visible

### Analysis tabs

| Tab | Contents |
|---|---|
| **Summary** | Packet count, duration, data size, protocol breakdown, top talkers |
| **Anomalies** | HIGH-severity rule-based findings (RST rate, retransmissions, etc.) |
| **Flows** | All conversation flows with packet/byte counts and stream viewer |
| **TCP** | Health counters — RSTs, retransmissions, zero-window events, problem streams |
| **UDP** | Large datagrams, one-sided flows, high-rate flows |
| **DNS** | Query summary — names, record types, response codes |
| **Threats** | Security findings — port scans, cleartext HTTP, credential risk, and more |

### Live feed (remote capture)

pktPCAP can receive a live pcapng stream from a remote host running `tshark` or Wireshark. The server buffers up to 200 MB per named session. The **Live Feeds** page has two tabs matching the two collection methods:

- **tshark** — generic curl-piped stream, works from any host with `tshark` + `curl` (see [Remote Collector — Software & Configuration](#remote-collector--software--configuration))
- **Wireshark GUI** — native SSH Remote Capture using the bundled `pktpcap` wrapper, giving you a live view in Wireshark itself while pktPCAP buffers the same stream (see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh))

**On the remote host (tshark method):**

```bash
tshark -i <interface> -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"
```

Retrieve the feed token and endpoint from **Settings → Capture Ingest**, then click **Load from Feed** in the Live Feeds page to pull the buffered capture into the normal analysis view.

---

## API Reference

All endpoints are served from the app root (default `http://your-host`).

### Settings

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings` | Return current settings (API keys masked after first 8 chars) |
| `POST` | `/api/settings` | Save settings; masked key values (containing `•`) are not overwritten |

### AI

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/ai` | Proxy a prompt + data array to the configured AI provider |
| `POST` | `/api/ai/test` | Test the active API key ("Say PONG") |

**`POST /api/ai` body:**

```json
{
  "prompt": "Analyze these flows for signs of lateral movement",
  "data": [{ "type": "text", "text": "..." }]
}
```

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/login` | Local username/password login |
| `POST` | `/api/logout` | End session |
| `GET` | `/api/auth/current-user` | Return current user info and role |
| `GET` | `/api/auth/saml/login` | Redirect to SAML IdP (if configured) |
| `POST` | `/api/auth/saml/callback` | SAML Assertion Consumer Service (ACS) callback — auto-provisions/role-syncs the user |
| `GET` | `/api/auth/saml/metadata` | SP metadata XML (register this with the IdP) |

### Users

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users` | List all users |
| `POST` | `/api/users` | Create a user |
| `PUT` | `/api/users/<id>` | Update a user |
| `DELETE` | `/api/users/<id>` | Delete a user |
| `POST` | `/api/users/<id>/reset-password` | Reset a user's password |
| `PATCH` | `/api/users/<id>/set-default-admin` | Mark a user as the default/fallback admin account |

### Notifications

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/notifications/test` | Send a real test message on one channel (`slack`, `email`, `pagerduty`, `webhook`, `tracecat`) using saved settings — returns `sent` / `skipped` (channel disabled or unconfigured) / `failed` |

### Database

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/db-config` | Return the current `config.json` (`db_type` / `db_path`) |
| `POST` | `/api/db-config/test` | Open a candidate SQLite path and run `SELECT 1` without switching to it |
| `POST` | `/api/db-config` | Switch the active database path |

### Backups

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/backup/run` | Run a backup snapshot immediately (same as "Run Backup Now" in Settings) |
| `GET` | `/api/backup/list` | List existing snapshots — name, size, files, created time |

### Suite Integration

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/suite/token` | Return the current suite token and whether one is set — for display in Settings |
| `POST` | `/api/suite/register` | Called **by pktHub** (not by an admin directly) to push/set this app's suite token during registration — body `{"suite_token": "..."}` |
| `POST` | `/api/suite/regenerate` | Generate a new local suite token, invalidating the old one — re-register in pktHub afterward |

### Logs

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/logs` | Query app logs (supports `?level=`, `?logger=`, `?limit=`, `?offset=`) |
| `GET` | `/api/logs/stats` | Log count by level and logger |
| `DELETE` | `/api/logs` | Clear all logs **(admin only)** |
| `POST` | `/api/logs/level?level=DEBUG` | Change the live log level |

### Live Feed

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/feed/<name>` | Stream pcapng data into a named session |
| `GET` | `/api/feeds` | List active feed sessions |
| `GET` | `/api/feeds/<name>/download` | Download buffered pcapng as a file |
| `DELETE` | `/api/feeds/<name>` | Clear and remove a session |

### Server

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/restart` | Graceful server restart |
| `GET` | `/api/health` | Public health check (used by pktHub) |

---

## Project Structure

```
pktpcap/
├── service/                    ← Application source (copied to the install dir by install.sh)
│   ├── server.py               ← Flask entry point — all routes, SAML, notifications, feeds
│   ├── db.py                   ← SQLite database layer, default settings, admin bootstrap
│   ├── backup_job.py           ← In-app scheduled/on-demand backup engine (Settings → Data → Backups)
│   ├── suite_client.py         ← pktpcap-as-client helper for calling a sibling pkt* app's suite API (not yet wired to a UI feature)
│   ├── logging_handler.py      ← SQLite async log ring-buffer
│   ├── requirements.txt
│   ├── config.json             ← Runtime config ({db_type, db_path}) — GITIGNORED
│   ├── static/
│   │   ├── index.html          ← Full single-page app (upload/analyze, live feeds, logs) — server-rendered via Flask + static assets, not a React SPA
│   │   ├── nav.js              ← Shared sidebar nav component
│   │   └── logo.png
│   ├── pktpcap                  ← Remote-capture wrapper script (renamed from pkt-capture) — used by Wireshark's SSH Remote Capture; installed at <install_dir>/pktpcap with __PORT__ substituted by install.sh
│   └── templates/
│       ├── login.html          ← Login page (local auth + SSO; Enter-to-submit)
│       └── settings.html       ← Settings UI (admin only) — General/Captures/Notifications/User Keys/Capture Ingest/Security (Users, Auth, Suite Integration, AI Assistant, SSL)/Data (Storage, Backups)
│
├── install.sh                   ← Interactive Ubuntu Server install script (see Installation)
├── pktpcap.service              ← systemd unit template (placeholders substituted by install.sh)
├── backup.py                    ← Standalone dev-machine checkout backup (2-rotation) — NOT the in-app feature; see backup_job.py above
│
├── scripts/
│   └── verify_deploy.py         ← SSH into a deployed host and check service/port/health
│
├── ssl/                        ← SSL certs — GITIGNORED (place certs here)
│   └── .gitkeep
│
├── favicon.ico / favicon.svg / icon-*.png ← App icons
└── lockup-*.png / lockup.svg   ← Logo assets
```

pktPCAP is **server-rendered** (Flask serving static HTML/JS + Jinja templates), not a React/Vite single-page app like some sibling `pkt*` tools — there's no separate frontend build step; editing `service/static/index.html` or the templates takes effect on the next request (or `POST /api/restart`).

---

## SSL / TLS

pktPCAP auto-detects SSL at startup by checking for `ssl/server.crt` and `ssl/server.key` relative to `server.py`. **File presence is authoritative** — the `ssl_enabled` database flag is not used for auto-detection. Place your cert and key in the `ssl/` directory and restart; pktPCAP will serve HTTPS automatically.

For PFX/PKCS#12 cert conversion:
```bash
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out ssl/server.crt
openssl pkcs12 -in cert.pfx -nocerts -nodes  -out ssl/server.key
```

The `ssl/` directory is gitignored — never commit certificate material.

---

## Sidebar / Navigation

`service/static/nav.js` is a shared component used by both `index.html` and `settings.html`. It renders the sidebar navigation and handles role-based visibility:
- Settings link is hidden for non-admin roles
- Clear Logs button is hidden for non-admin roles

Both pages fetch `/api/auth/current-user` to populate the user/logout footer.

---

## Architecture Notes

**Path resolution:** `BASE = Path(__file__).parent` throughout — the server resolves all paths (static files, `ssl/`, `config.json`, screenshots) relative to `server.py`, regardless of the current working directory it's launched from.

**Backup scheduler:** `service/backup_job.py` starts a daemon thread at boot that sleeps for `backup_interval_hours` and runs a snapshot whenever `auto_backup` is on; "Run Backup Now" and `POST /api/backup/run` call the same `run_backup()` function directly, outside the schedule.

**Remote-capture wrapper:** `service/pktpcap` (installed at `<install_dir>/pktpcap`) is invoked by Wireshark as its SSH Remote Capture command in place of `dumpcap`. It checks `wireshark_capture_enabled` via `/api/settings`, then tees `dumpcap`'s output: one stream goes back over the SSH pipe to Wireshark's GUI, the other is POSTed to this server's own `/api/feed/<name>` endpoint using the same feed-token auth as the generic tshark method.

**AI proxy:** The frontend calls `localAsk(prompt, dataArray)` which POSTs to `/api/ai`. The server forwards the request to Anthropic or OpenAI and streams the response back. API keys never leave the host.

**Log capture:** A background daemon thread drains a `queue.Queue` of log records into the `app_logs` SQLite table. The ring buffer is capped at 10,000 rows; oldest rows are purged on each flush cycle.

**Server restart:** `POST /api/restart` spawns `subprocess.Popen([sys.executable] + sys.argv)`, then calls `os._exit(0)` after 0.8 s. The new process is ready before the old one exits — the browser reconnects automatically.

**API key masking:** `GET /api/settings` returns keys as `sk-ant-api0•••...`. `POST /api/settings` skips overwriting a field if the submitted value contains a `•` character, preventing accidental key erasure.

**pktHub integration:** The app accepts an `X-Suite-Token` header on every request. A matching token establishes a Flask session as the forwarded user/role, enabling pktHub to proxy requests without a separate login flow.

---

## Supported AI Models

| Provider | Models |
|---|---|
| Anthropic | `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5-20251001` |
| OpenAI | `gpt-4o`, `gpt-4o-mini`, `o1`, and any model name entered manually |

---

## License

MIT
