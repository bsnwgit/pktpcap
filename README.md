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
- In-app log viewer, user management, SSL support, and a live pcapng feed endpoint
- Docker-native — pull and run in minutes, data persists across updates

---

## Quick Start — Docker

```bash
# 1. Clone the repo
git clone https://github.com/bsnwgit/pktpcap.git
cd pktpcap

# 2. Configure
cp .env.example .env
# Edit .env — set APP_ADMIN_PASSWORD at minimum

# 3. (Optional) Add SSL certs
# Place server.crt + server.key in the ssl/ directory, then enable SSL in Settings

# 4. Start
docker compose up -d

# 5. Open
# http://your-host   (or https://your-host if SSL is configured)
```

The first start seeds the admin user from `.env` and persists all data to named Docker volumes.

---

## Docker — Volumes

| Volume | Mount | Purpose |
|---|---|---|
| `pktpcap_data` | `/data` | SQLite database, app config, users, settings |
| `pktpcap_storage` | `/storage` | PCAP uploads, screenshots |
| `./ssl` | `/app/ssl` | TLS certificate and key (bind mount) |

Volumes survive `docker compose pull && docker compose up -d` upgrades — your data is never overwritten by an image update.

---

## Docker — Environment Variables

Copy `.env.example` to `.env` and configure before first run.

| Variable | Default | Description |
|---|---|---|
| `APP_ADMIN_PASSWORD` | *(required)* | Admin password — startup fails if blank |
| `APP_ADMIN_USER` | `admin` | Admin username (first-run only) |
| `APP_ADMIN_EMAIL` | — | Admin email (optional) |
| `APP_PORT` | `80` | Port the app listens on inside the container |
| `APP_HTTP_PORT` | `80` | External HTTP port on the host |
| `APP_HTTPS_PORT` | `443` | External HTTPS port on the host |
| `APP_STORAGE_PATH` | `/storage` | Container path for PCAP storage |

---

## Docker — SSL / TLS

1. Place `server.crt` and `server.key` in the `ssl/` directory next to `docker-compose.yml`.
2. Restart the container: `docker compose restart`
3. Open Settings → enable SSL.
4. Access via `https://your-host`.

For PFX/PKCS#12 conversion:
```bash
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out ssl/server.crt
openssl pkcs12 -in cert.pfx -nocerts -nodes  -out ssl/server.key
```

The `ssl/` directory is gitignored — never commit certificate material.

---

## Docker — Image

Pre-built images are published to GitHub Container Registry on every push to `main` and `feature/docker`:

```bash
docker pull ghcr.io/bsnwgit/pktpcap:latest
```

Images are tagged `:latest` and `:<git-sha>` for pinning.

To build locally:
```bash
docker build -t pktpcap .
```

Then in `docker-compose.yml`, replace `image: ghcr.io/bsnwgit/pktpcap:latest` with `build: .`.

---

## Manual Setup (without Docker)

### 1. Clone

```bash
git clone https://github.com/bsnwgit/pktpcap.git
cd pktpcap
```

### 2. Install dependencies

```bash
pip install -r service/requirements.txt
```

### 3. Run

```bash
cd service
python server.py
```

The app opens at **http://localhost** by default (port 80). To use a different port, change the `port` setting in the app's Settings page or set it in the database.

### 4. Add an API key (optional)

Go to **Settings** and enter your Anthropic or OpenAI API key. Without a key the rule-based parser still works — only the AI assistant panel requires one.

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
- `<feed-token>` — token from pktPCAP Settings page
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
| File analysis | Parse `.pcap` / `.pcapng` up to 500 MB (configurable) |
| Seven analysis tabs | Summary, Anomalies, Flows, TCP, UDP, DNS, Threats |
| AI assistant | Anthropic Claude or OpenAI GPT — proxied through the local server |
| Three analysis modes | Specific Issue · Auto-Triage · Security Review |
| Live feed | Remote `tshark`/Wireshark hosts can stream pcapng directly to the server |
| In-app log viewer | SQLite ring-buffer of app logs, queryable from the Logs page |
| User management | Create/edit/delete local users with password reset |
| Role-based access | `admin`, `analyst`, `viewer` — Settings and log clear require admin |
| SAML SSO | Okta integration via `python3-saml` |
| SSL/HTTPS | Auto-detected from `ssl/` directory; custom cert path configurable in Settings |
| Settings UI | Web UI at `/settings` — no config file editing needed |
| Docker | Single-container deployment; data persists in named volumes |
| pktHub integration | Suite-token header auth for embedding in the pktHub dashboard suite |

---

## Requirements

- Python 3.10+
- pip packages: see `service/requirements.txt`
- System packages (for SAML): `libxml2-dev`, `libxmlsec1-dev` (installed automatically in Docker)

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

Settings managed via the UI (`/settings`):

| Key | Default | Description |
|---|---|---|
| `port` | `80` | Listening port |
| `provider` | `anthropic` | AI provider (`anthropic` or `openai`) |
| `anthropic_key` | — | Anthropic API key |
| `anthropic_model` | `claude-opus-4-8` | Model string |
| `openai_key` | — | OpenAI API key |
| `openai_model` | `gpt-4o` | Model string |
| `ssl_enabled` | `false` | Enable HTTPS (**file presence in `ssl/` is authoritative**) |
| `ssl_cert` / `ssl_key` | — | Cert/key paths (overridden by `ssl/server.crt` + `ssl/server.key` if present) |
| `storage_path` | — | Where uploaded captures are saved |
| `max_upload_mb` | `500` | Upload size limit |
| `storage_quota_gb` | `50` | Total storage cap |
| `retention_days` | `90` | Auto-delete captures older than N days |
| `auto_purge` | `false` | Enable automatic retention enforcement |

---

## Usage

### Analyzing a capture file

1. Open the app in your browser
2. Drag-and-drop a `.pcap` or `.pcapng` file onto the upload zone, or click to browse
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

pktPCAP can receive a live pcapng stream from a remote host running `tshark` or Wireshark. The server buffers up to 200 MB per named session.

**On the remote host:**

```bash
tshark -i <interface> -w - | curl -s \
  -H "Authorization: Bearer <feed-token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @- \
  "http://<pktpcap-host>/api/feed/<session-name>"
```

Retrieve the feed token from the Settings page, then load the buffered capture from the UI.

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
| `POST` | `/api/auth/saml/acs` | SAML Assertion Consumer Service callback |

### Users

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users` | List all users |
| `POST` | `/api/users` | Create a user |
| `PUT` | `/api/users/<id>` | Update a user |
| `DELETE` | `/api/users/<id>` | Delete a user |
| `POST` | `/api/users/<id>/reset-password` | Reset a user's password |

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
├── service/                    ← Application source
│   ├── server.py               ← Flask entry point
│   ├── db.py                   ← SQLite database layer
│   ├── logging_handler.py      ← SQLite async log ring-buffer
│   ├── requirements.txt
│   ├── config.json             ← Runtime config — GITIGNORED
│   ├── static/
│   │   ├── index.html          ← Full single-page app
│   │   ├── nav.js              ← Shared sidebar nav component
│   │   └── logo.png
│   └── templates/
│       ├── login.html          ← Login page (local auth + SSO)
│       └── settings.html       ← Settings UI (admin only)
│
├── Dockerfile                  ← Container build
├── docker-compose.yml          ← Compose stack (recommended)
├── docker_init.py              ← Container first-run bootstrap
├── entrypoint.sh               ← Container entrypoint
├── .env.example                ← Environment variable template
│
├── ssl/                        ← SSL certs — GITIGNORED (place certs here)
│   └── .gitkeep
│
├── .github/
│   └── workflows/
│       └── docker.yml          ← CI: build + push to GHCR on push to main/feature/docker
│
├── favicon.ico / icon-*.png    ← App icons
└── lockup-*.png / lockup.svg   ← Logo assets
```

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

**Path resolution:** `BASE = Path(__file__).parent` throughout — the server resolves all paths relative to `server.py`, so it works identically whether run directly or inside a container.

**AI proxy:** The frontend calls `localAsk(prompt, dataArray)` which POSTs to `/api/ai`. The server forwards the request to Anthropic or OpenAI and streams the response back. API keys never leave the host.

**Log capture:** A background daemon thread drains a `queue.Queue` of log records into the `app_logs` SQLite table. The ring buffer is capped at 10,000 rows; oldest rows are purged on each flush cycle.

**Server restart:** `POST /api/restart` spawns `subprocess.Popen([sys.executable] + sys.argv)`, then calls `os._exit(0)` after 0.8 s. The new process is ready before the old one exits — the browser reconnects automatically.

**API key masking:** `GET /api/settings` returns keys as `sk-ant-api0•••...`. `POST /api/settings` skips overwriting a field if the submitted value contains a `•` character, preventing accidental key erasure.

**pktHub integration:** The app accepts an `X-Suite-Token` header on every request. A matching token establishes a Flask session as the forwarded user/role, enabling pktHub to proxy requests without a separate login flow.

---

## Supported AI Models

| Provider | Models |
|---|---|
| Anthropic | `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001` |
| OpenAI | `gpt-4o`, `gpt-4o-mini`, and any model name entered manually |

---

## License

MIT
