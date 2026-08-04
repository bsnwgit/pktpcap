# pktPCAP

<p align="center">
  <img src="lockup-256h.png" alt="pktPCAP" height="64">
</p>

<p align="center">
  A standalone FastAPI/React web app for analyzing PCAP files in the browser, with an AI chat assistant and a live NetFlow-style capture feed.
</p>

---

## Overview

pktPCAP is a locally-hosted packet capture analyzer. Drop a `.pcap` or `.pcapng` file onto the UI and get instant, rule-based analysis of TCP health, DNS, threats, and traffic flows — no cloud upload required. An optional AI assistant (local/self-hosted via Ollama or any OpenAI-compatible endpoint, or cloud via Anthropic/OpenAI) is available as a floating chat panel on every page, and can answer questions about whatever capture you're currently viewing.

**Key traits:**
- Runs entirely on your infrastructure — captures never leave your environment
- Works without an API key (rule-based analysis only)
- React 18 / Vite single-page app, FastAPI backend — same stack as the rest of the `pkt*` suite
- Client-side packet parsing (TypeScript) — a `.pcap`/`.pcapng` file never touches the server unless you explicitly choose "Analyze & Save"
- In-app log viewer, user management, Okta SAML SSO, SSL/TLS, and a live pcapng feed endpoint (generic tshark/curl **or** native Wireshark GUI remote capture)
- IP Lookup on every IP shown in the analyzer (ipinfo.io / ipapi.is / AbuseIPDB / MXToolbox for public IPs, pktIPAM inventory lookup for private IPs)
- Multi-channel alert notifications (Slack, Email, PagerDuty, generic webhook, Tracecat) and scheduled/on-demand backups
- Deploys as a systemd service on Ubuntu Server bare metal — no container runtime required

---

## Recent Changes (2026-08)

- **Persisted capture sharing.** Captures (uploads and tshark/Wireshark pushes) are now attributed to the user who created them, with a per-capture "shared" flag the owner or an admin can toggle so other users see it labeled "Shared by `<username>`". Unowned captures (Wireshark SSH pushes with no pktPCAP user context) stay visible to everyone, unchanged from before. The Upload page now has its own **Persisted Captures** box (in addition to Live Feeds'), each filtered to its own source so the two lists don't overlap.

## Recent Changes (2026-08)

- **AI Assistant chat error messages fixed.** A connection/timeout failure reaching a provider (e.g. Ollama unreachable) used to surface as a blank message like `"Ollama error:"` with no detail — httpx's own connection/timeout exceptions often carry no message text. It now names the provider and its base URL, or the failure type when nothing else is available. (pktPCAP's chat request already sent proper auth via `api.aiChat()`, so it wasn't affected by the auth bug fixed the same day in several sibling apps — see their READMEs.)

## Recent Changes (2026-07)

- **Rebuilt as FastAPI + React.** pktPCAP was the first app in the `pkt*` suite, originally a synchronous Flask app with server-rendered Jinja templates, cookie-session auth, and sha256 password hashing. It's now a FastAPI backend (`app/`) + React 18/Vite SPA (`frontend/`) with JWT/bcrypt auth, matching every sibling app's stack. The old Flask app is left in place under `service/` for reference but is **not used** by `install.sh` or the systemd unit anymore — see [Project Structure](#project-structure).
- **New `captures` database table.** Persisted `.pcapng` files (from an upload or a finished live feed) now have a real DB row (`saving`/`saved`/`failed`/`missing`) instead of being tracked purely by directory listing — a crash mid-write is now visible instead of silently absent.
- **IP Lookup wired into the Analyzer.** Every IP shown in Top Talkers, Flows, TCP streams, UDP flows, and Threat evidence is now a clickable lookup (`IpLink` component) — external providers for public IPs, a pktIPAM inventory lookup for private/RFC1918 IPs (if a pktIPAM Suite Integration is configured).
- **tshark ingest can now be toggled off independently of Wireshark remote capture**, and a default capture duration can be set so a `curl`-piped tshark session can self-terminate cleanly instead of relying on Ctrl+C (which truncates the upload).
- **AI is now a persistent chat assistant** (floating button, bottom-right, on every page) rather than three preset "analysis mode" buttons — ask a free-form question and it uses whatever capture/analysis context is currently on screen.
- Config split into two layers: `config.yaml` (startup/infrastructure — port, JWT secret, CORS, install dir) and the SQLite `settings` table (everything else, managed from the Settings UI) — see [Configuration](#configuration).

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
4. Copy `app/`, `migrations/`, and the capture wrapper script into the install directory
5. Generate `config.yaml` from `config.example.yaml` (random JWT secret, port filled in)
6. Apply database migrations and create the `admin` account with a **random password**, printed once to the terminal — save it, it is never shown again
7. Build the React frontend with `npm` (if Node.js/npm is available — see the note below if it isn't)
8. Install, enable, and start the `pktpcap` systemd service
9. Open the port in `ufw` automatically, if `ufw` is installed (otherwise it prints a reminder to open it manually)

At the end it prints a boxed summary with the URL and admin credentials (on a fresh install only — an existing database is left untouched and the box says so instead).

Open `http://<server-ip>:<port>` (default port `8765`) and log in with the `admin` username and the generated password from the install output.

**Node.js requirement:** the installer builds the frontend with `npm run build` if `npm` is on `PATH`. If it isn't, the service still installs and starts, but the web UI returns `{"detail":"Not Found"}` until you build it manually:
```bash
cd <repo-checkout>/frontend && npm install && npm run build
mkdir -p <install_dir>/frontend && cp -r dist <install_dir>/frontend/dist
sudo systemctl restart pktpcap
```

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
| `PKTPCAP_INSTALL_DIR` | `/opt/pktpcap` | Where the app is installed — becomes `install_dir` in `config.yaml`, which every other on-disk path (db, logs, ssl, captures) defaults under |
| `PKTPCAP_PORT` | `8765` | Listening port; written into `config.yaml`, the `pktpcap` remote-capture wrapper, and opened in `ufw` |
| `PKTPCAP_LOG_DIR` | `$PKTPCAP_INSTALL_DIR/logs` | systemd stdout/stderr log file location |
| `PKTPCAP_SERVICE_USER` | current user | User the systemd service runs as |
| `PKTPCAP_SERVICE_GROUP` | same as service user | Group the systemd service runs as |
| `PKTPCAP_ADMIN_PASSWORD` | (not read by `install.sh`) | `install.sh` always generates its own random password for the initial admin account. This variable is only honored if you run `app.database.seed_admin()` yourself outside the installer (e.g. bootstrapping a database by hand) |

---

## Installation

`install.sh` (see [Quick Start](#quick-start)) automates every step below. This section is the full manual walkthrough — useful to customize the install, run steps individually, or understand what the script does.

### 1. Clone the repository

```bash
git clone https://github.com/bsnwgit/pktpcap.git
cd pktpcap
```

### 2. System packages

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config gcc \
    curl ca-certificates
```

`libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config`, and `gcc` are required to build `python3-saml`'s xmlsec native bindings (used for Okta SAML SSO).

### 3. Install Python dependencies

```bash
python3 -m venv /opt/pktpcap/venv
/opt/pktpcap/venv/bin/pip install -r requirements.txt
```

### 4. Copy application files

```bash
cp -r app migrations /opt/pktpcap/
cp scripts/pktpcap /opt/pktpcap/pktpcap
sed -i "s#__PORT__#8765#g" /opt/pktpcap/pktpcap
chmod +x /opt/pktpcap/pktpcap
mkdir -p /opt/pktpcap/ssl /opt/pktpcap/captures
```

The `ssl/` directory is where you place `server.crt` + `server.key` for HTTPS certs (see [SSL / TLS](#ssl--tls)); `captures/` is the default location persisted `.pcapng` files are written to.

### 5. Configure

```bash
cp config.example.yaml /opt/pktpcap/config.yaml
# Generate a real JWT secret:
sed -i "s/CHANGE_ME_generate_with_openssl_rand_hex_32/$(openssl rand -hex 32)/" /opt/pktpcap/config.yaml
echo 'install_dir: "/opt/pktpcap"' >> /opt/pktpcap/config.yaml
```

`config.yaml` only covers startup/infrastructure settings (host, port, JWT secret, CORS, install dir). Everything else — capture storage/retention, notification channels, AI keys, SAML config, suite integrations, per-user lookup API keys — lives in the SQLite `settings` table, created automatically on first start and managed entirely through the **Settings** UI once you've logged in.

### 6. Apply migrations and create the admin user

```bash
cd /opt/pktpcap
PKTPCAP_CONFIG=/opt/pktpcap/config.yaml \
PKTPCAP_INSTALL_DIR=/opt/pktpcap \
PKTPCAP_ADMIN_PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)" \
venv/bin/python3 -c "
import asyncio
from app.database import init_db, seed_admin
async def setup():
    await init_db()
    await seed_admin()
asyncio.run(setup())
"
```

If `PKTPCAP_ADMIN_PASSWORD` is unset and the `users` table is empty, `seed_admin()` refuses to start with a clear error rather than silently creating an account with no password — there is no `admin`/`admin` fallback in this rebuild.

### 7. Build the frontend

```bash
cd frontend
npm install
npm run build
mkdir -p /opt/pktpcap/frontend
cp -r dist /opt/pktpcap/frontend/dist
```

FastAPI serves the built SPA directly from `frontend/dist` relative to the install dir (see `app/main.py`) — there's no separate web server needed in front of it.

### 8. Install the systemd service

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

The unit's `ExecStart` runs `venv/bin/python -m app.server`, which reads `host`/`port` from `config.yaml` at each start — changing the port only needs `config.yaml` rewritten + a restart, not a unit file edit. It grants `CAP_NET_BIND_SERVICE` in case you set a port below 1024 — the default (`8765`) doesn't need it.

**Workers must stay at 1.** Live capture feed sessions (`app/capture/feed_sessions.py`) are held in the single worker process's memory — a multi-worker deployment would silently split feed ingest/list/download across processes and lose in-progress captures. Don't add `--workers` flags without redesigning feed storage to be shared (disk/Redis).

### 9. Open the firewall

```bash
sudo ufw allow 8765/tcp
```

### 10. Verify

```bash
curl -s http://localhost:8765/api/health
```

Log in at `http://<server-ip>:8765` with `admin` and the password printed by step 6.

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
│         ▼ drag-and-drop / file picker (Upload page)              │
│  [Browser — React SPA]                                           │
│         │                                                        │
│         ├─ parsePCAP() ──► TS packet parser (pure client-side)   │
│         │                  builds flows, TCP stats, DNS, threats  │
│         │                                                        │
│         ├─ Rule engine ──► anomaly/threat detection (no server)  │
│         │                                                        │
│         └─ POST /api/ai/chat ─► [pktPCAP FastAPI server]         │
│                                  │                               │
│                                  ▼                               │
│              [Ollama/local, Anthropic, or OpenAI]  (optional)    │
│                                  │                               │
│                                  ▼                               │
│                     AI Assistant chat panel                      │
└──────────────────────────────────────────────────────────────────┘
```

**What happens step by step:**

1. On the **Upload** page, the user drops a `.pcap` or `.pcapng` file, or clicks to browse — multiple files can be queued.
2. **Analyze (local)** reads the file entirely client-side and never sends it anywhere; **Analyze & Save** also `POST`s it to `/api/captures/upload` so it's persisted and shows up in the **Persisted Captures** box on the Upload page (and, if shared, in other users' lists too). Uploads are private to the uploader by default — check **Share with other users** to change that.
3. `parsePCAP()` (`frontend/src/lib/pcap/parser.ts`) walks every packet record and builds in-memory data structures: flow tuples, TCP flag counters, DNS query tables, and threat indicators (`analyze.ts`).
4. Rule-based analysis runs immediately in the browser — no server round-trip needed. Results render across seven tabs on the **Analyzer** page.
5. If an AI provider is enabled and configured, the floating **AI Assistant** panel (available on every page) can answer free-form questions about the current capture — it POSTs the question plus whatever analysis context is on screen to `/api/ai/chat`, which the server forwards to whichever provider is enabled (local/self-hosted first, then Anthropic or OpenAI).

**Server role in local mode:** the FastAPI server is only involved for `/api/captures/upload` (if you choose to save) and the AI chat proxy. Packet parsing and rule-based analysis are entirely client-side.

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
│         │   (chunked reads from request.stream, one worker process only)     │
│         │                                                                    │
│         └─ Session stays "connected" until curl closes the connection        │
│                                                                              │
│  On disconnect ─► if a Captures storage path is configured, the buffered     │
│                    bytes are saved to disk and tracked as a `captures` row   │
│                                                                              │
│  GET /api/feeds                     ─► list active sessions + bytes buffered │
│  GET /api/captures                  ─► list persisted captures (DB-backed)   │
│  GET /api/feeds/<name>/download     ─► download a still-active session      │
│  GET /api/captures/<fname>/download ─► download a persisted capture         │
│  DELETE /api/feeds/<name> / /api/captures/<fname>                            │
│                                                                              │
│  [User clicks Analyze] ──► same client-side parse/analysis path as Mode 1   │
└──────────────────────────────────────────────────────────────────────────────┘
```

**What happens step by step:**

1. On the **Live Feeds** page, the user fills in a session name, interface, optional BPF filter, and optional duration — the page builds the exact `tshark | curl` command (including the real feed token) to copy-paste onto the remote host.
2. On the remote capture host, `tshark` captures packets on the chosen interface and writes raw pcapng to stdout; the output is piped to `curl`, which streams it as an HTTP POST to `/api/feed/<name>`.
3. pktPCAP validates the Bearer token and appends incoming chunks to a named `FeedSession` buffer (up to 200 MB; bytes beyond the cap are silently dropped and `truncated` is flagged).
4. While the feed is active, **Active Feed Sessions** on the Live Feeds page auto-refreshes (every 5s) showing status, remote address, bytes, and duration.
5. When the capture ends (curl disconnects), pktPCAP saves the buffered bytes to the configured capture storage path (if any) and records it in the `captures` table with status `saved` — the in-memory session is then dropped so a finished push doesn't linger in the "active" list.
6. Clicking **Analyze** on either an active session or a persisted capture pulls the buffered/saved bytes into the same client-side parse/analysis flow as Mode 1.
7. A session or capture can be deleted at any point via the trash-can/Delete action.

---

### Remote Collector — Software & Configuration

The remote capture host needs only two tools: **tshark** and **curl**. Both are available on Linux, macOS, and Windows.

#### tshark

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
| `-a duration:<seconds>` | Auto-stop after N seconds — lets tshark end itself cleanly instead of relying on Ctrl+C |

**Listing available interfaces:** `tshark -D` on the **remote** host actually running the capture.

> **Note on the Live Feeds page's Interface field:** it's a free-text field with datalist suggestions drawn from `GET /api/system/net-interfaces`, which returns **pktPCAP server's own** interfaces (`socket.if_nameindex()`). Those suggestions are only meaningful for the Wireshark GUI method below, since that traffic runs on the pktPCAP host itself. For the tshark/CLI method, type the **remote host's** real interface name (from `tshark -D` run on that host) — pktPCAP has no way to introspect an arbitrary remote box in advance, so the suggested list doesn't apply there. This UX gap is described in the field's help text but not otherwise resolved.

#### curl

curl handles the HTTP transport. **Use `-T -` (upload-file from stdin), not `--data-binary @-`** — `--data-binary` has to read all of stdin into memory first so it can send a `Content-Length` header, so the entire capture uploads in one burst only once tshark exits, and the session never shows up in Active Feed Sessions while it's running. `-T -` uses chunked `Transfer-Encoding` instead and streams each chunk as tshark produces it, which is what makes the live session visible. `-T` defaults to the PUT method, so pair it with an explicit `-X POST`.

#### Feed command (generated by the Live Feeds page)

```bash
tshark -i <interface> [-f "<filter>"] [-a duration:<seconds>] -w - | curl -sS -X POST \
  -H "Authorization: Bearer <feed-token>" \
  -T - \
  "http://<pktpcap-host>:<port>/api/feed/<session-name>"
```

The Live Feeds page fills in every placeholder for you (session name, interface, filter, duration, token, host/port) and gives you a **Copy Command** button. Don't stop a running capture with Ctrl+C — it kills `curl` along with `tshark` in the same keystroke, which usually truncates the upload; set a **Duration** in the builder instead so the capture stops itself with time to finish uploading.

**HTTPS (if pktPCAP has SSL enabled):** use `https://` and add `-k` to skip cert verification for self-signed certs (or `--cacert <cert.pem>` for proper validation).

**Allow/deny toggle:** an admin can disable tshark/CLI ingest independently of the Wireshark method via the **Allow tshark / CLI captures** toggle on the Live Feeds page (`tshark_capture_enabled` setting) — pushes to `/api/feed/<name>` from a non-Wireshark session name are rejected with 403 while it's off.

#### Running as a background service (Linux systemd)

To run the feed continuously and restart automatically:

**`/etc/systemd/system/pktpcap-feed.service`:**
```ini
[Unit]
Description=pktPCAP Live Feed — <interface>
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'tshark -i <interface> -w - | curl -s -X POST \
  -H "Authorization: Bearer <feed-token>" \
  -T - \
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

This is powered by a small wrapper script, **`pktpcap`** (`scripts/pktpcap` in the repo, installed at `<install_dir>/pktpcap`). Wireshark SSHes into the pktPCAP host and runs this wrapper instead of `dumpcap` directly; the wrapper tees the capture — one copy goes to Wireshark over the SSH pipe, the other is POSTed to pktPCAP's own `/api/feed/<name>` endpoint using the same buffered-session mechanism as the tshark method.

**Enable it:** Live Feeds page → **Wireshark CLI** or **Wireshark UI** tab → toggle **Allow Wireshark SSH Remote Capture** on (admin only; non-admins see "Ask an admin to change this"). Feed tokens and endpoint config are read from a small unauthenticated endpoint (`GET /api/capture/wrapper-config`) built specifically for this wrapper script, since the general `/api/settings` now requires a real login under the FastAPI rebuild.

This uses Wireshark's built-in **sshdump** extcap interface (labeled "SSH remote capture: sshdump" in Wireshark's interface list) — **not** the older "Manage Interfaces → Remote Interfaces" dialog, which is a different, rpcap-based Windows feature unrelated to SSH.

**Wireshark CLI tab:** generates a single `wireshark -k -i sshdump -o extcap.sshdump.<option>:"<value>" ...` command that launches Wireshark pre-configured and starts capturing immediately — copy-paste-and-run, same as the tshark/curl tab.

**Wireshark UI tab:** walks through the same setup in Wireshark's own settings dialog — click the gear/wrench icon next to the sshdump interface, then set:

| Field | Value |
|---|---|
| Remote SSH server address | pktPCAP server IP |
| Remote SSH server port | 22 (or your SSH port) |
| Username | a user with permission to run `dumpcap` (see the group note below) |
| Authentication | SSH public key, or password |
| Remote Capture Command | `<install_dir>/pktpcap -i <interface> [-f '<filter>'] -w -` (default install dir `/opt/pktpcap`) |

**Important:** sshdump uses the Remote Capture Command exactly as given — it does **not** append the separate "Remote Interface" or "Remote Capture Filter" fields for you (confirmed against [sshdump's own docs](https://www.wireshark.org/docs/man-pages/sshdump.html): "this command will be used as is"). The interface and any BPF filter have to be baked directly into the command string, as shown above — both tabs on the Live Feeds page already do this for you.

The wrapper checks `wireshark_capture_enabled` before running and exits with an error if it's off, so leaving Wireshark configured but the toggle disabled fails safely rather than silently.

> **Note:** on the pktPCAP host, running `dumpcap` over SSH still needs either `root` or a user in the `wireshark` group with `dumpcap` setuid permissions — same requirement as the generic tshark method above.

Once a live Wireshark session is running, its captured bytes are also visible from the pktPCAP UI as a normal entry in **Active Feed Sessions** — click **Analyze** to pull them in for the same rule-based/AI analysis as an uploaded file.

**Expected: a red "Error from extcap pipe" message when you stop the capture.** This comes from **Wireshark itself**, running on whatever machine you launched it from — it is not a pktPCAP error, and it does not mean the capture failed. Wireshark's sshdump extcap logs harmless SSH connection-setup warnings (typically `ssh_config_parse_line: Unsupported option: ...`, from libssh being pickier than OpenSSH about directives in your `~/.ssh/config`) to stderr when it connects, and Wireshark holds onto that stderr buffer and displays it as an "Error" banner the moment the capture pipe closes — regardless of whether the buffered content was actually an error. This is a known, filed Wireshark bug ([gitlab.com/wireshark/wireshark/-/issues/15845](https://gitlab.com/wireshark/wireshark/-/issues/15845)), purely client-side, with nothing pktPCAP can do to suppress it. If the capture otherwise shows "Capture started" → "Capture stopped" with no other complaint, it worked correctly.

---

### Feed Session Lifecycle

```
tshark starts → POST /api/feed/<name> opens → session.connected = True
                                                    │
                               data flows in chunks
                                                    │
tshark stops → curl closes connection → session.connected = False
                                                    │
                    if a Captures storage path is configured:
                        bytes are written to disk, a `captures` row is
                        created (status=saved), the in-memory session is
                        dropped from the "active" list
                    else:
                        buffer persists in memory until the user downloads/
                        analyzes it, DELETE /api/feeds/<name>, or a restart
```

Buffer limit is **200 MB per named session**. If the stream exceeds this, the session's `truncated` flag is set and additional bytes are discarded. Monitor usage via `GET /api/feeds`.

---

## Features

| Feature | Description |
|---|---|
| File analysis | Parse `.pcap` / `.pcapng` / `.cap`; drop multiple files to queue, analyze locally or save to server storage |
| Seven analysis tabs | Summary, Anomalies, Flows, TCP, UDP, DNS, Threats |
| AI Assistant | Floating chat panel (any page) — Ollama/local, Anthropic, or OpenAI, proxied through the local server, using the current view's capture context |
| IP Lookup | Every IP in the Analyzer is clickable: ipinfo.io / ipapi.is / AbuseIPDB / MXToolbox for public IPs (per-user API keys), pktIPAM inventory lookup for private IPs (via Suite Integration) |
| Live feed — tshark/curl | Any remote host with `tshark` streams pcapng directly to the server over HTTP; independently toggleable on/off |
| Live feed — Wireshark GUI | Native Wireshark SSH Remote Capture support via the bundled `pktpcap` wrapper script — see [Wireshark GUI remote capture](#wireshark-gui-remote-capture-ssh) |
| Persisted captures | Uploaded or feed-saved `.pcapng` files tracked in a `captures` DB table (status: saving/saved/failed/missing) — not just a directory listing |
| Capture sharing | Captures are private to the uploader/pusher by default; owner or admin can toggle **shared** so every user sees it ("Shared by `<username>`"); unowned pushes (e.g. Wireshark SSH) stay visible to all |
| In-app log viewer | SQLite-backed app logs, queryable from the Logs page with pagination; live log-level change from the UI |
| User management | Create/edit/delete local users with password reset; designate a default admin |
| Role-based access | `admin`, `analyst`, `viewer` — Settings, log clearing, and admin-only routes enforced server-side |
| SAML SSO | Okta integration via `python3-saml`, with auto-provisioning and role-sync from IdP attributes on login |
| Auto-login fallback | If both local auth and SAML are disabled, the Login page calls `/api/auth/auto-login` and signs in as the default admin automatically instead of showing a dead-end form |
| Alert notifications | Slack, Email (SMTP), PagerDuty, generic Webhook, and Tracecat — each independently enabled with a built-in test-send button |
| Scheduled + on-demand backups | Snapshots the SQLite DB and `config.json`/config on an interval, with rotation; "Run Backup Now" in Settings. Restore directly from any listed snapshot (no download/upload needed) or from an uploaded bundle, either restoring everything or just the files you pick |
| SSL/HTTPS | Upload a PEM cert+key or a PFX/PKCS#12 bundle from the Settings UI; status/expiry shown, no manual file placement required |
| Settings UI | Web UI at `/settings` — no config file editing needed for anything except startup/infra values |
| Suite Integration (outbound) | Named connections to sibling `pkt*` apps (currently used for the pktIPAM internal-IP lookup) |
| Suite Integration (inbound) | Accepts an `X-Suite-Token` header from pktHub (or another suite app) for proxied auth — no separate login flow needed when embedded |
| Deployment | systemd service on Ubuntu Server 22.04/24.04 LTS (bare metal); no container runtime required |

---

## Requirements

- Python 3.10+
- Node.js/npm (to build the frontend — see the [Quick Start](#quick-start) note if it's unavailable at install time)
- pip packages: see `requirements.txt` (repo root)
- System packages (for SAML): `libxml2-dev`, `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config`, `gcc` (installed by `install.sh`)

---

## Configuration

Configuration is split into two layers:

- **`config.yaml`** — startup/infrastructure settings that must be known before the database connects: `host`, `port`, `workers` (must stay `1`), `install_dir`, `secret_key` (JWT signing), `cors_origins`, `log_level`/`log_file`, `ssl_dir`, `storage_path`. Copy `config.example.yaml` to `<install_dir>/config.yaml` (or point `PKTPCAP_CONFIG` at it) and restart to change any of these. Every path defaults to somewhere under `install_dir`, so nothing needs to be set explicitly unless you want it somewhere else.
- **SQLite `settings` table** — everything else (capture retention, notification channels, AI provider keys, SAML config, suite integrations, per-user lookup API keys). Managed entirely through the **Settings** UI, organized into tabs: General, Security (Users, Auth, Suite Integration, AI Assistant, SSL/TLS), Data (Storage, Backups), Notifications, User Keys, Captures, Capture Ingest.

### General

| Setting | Description |
|---|---|
| App name / branding | Displayed in the browser tab and header |
| Timezone | Affects display of timestamps in the UI |

Port lives in `config.yaml`, not this tab — see [Security → Port](#security--auth) below.

### Captures (admin only)

| Setting | Description |
|---|---|
| Storage path | Directory where persisted capture files are written — required before feed sessions or uploads can be saved to disk |
| Retention / quota | Retention window and disk quota for stored captures |

### Capture Ingest (admin only)

| Setting | Description |
|---|---|
| `tshark_capture_enabled` | Allow generic tshark/curl pushes to `/api/feed/<name>` |
| `wireshark_capture_enabled` | Allow the Wireshark SSH Remote Capture wrapper to push |
| `feed_token` | Bearer token required on every `POST /api/feed/<name>` request |
| `default_capture_duration_seconds` | Pre-fills the Duration field in the Live Feeds command builder |

### Notifications

Each channel has its own enable toggle and a **Test** button (`POST /api/settings/test-notification`) that sends a real test message using the saved settings: **Slack** (incoming webhook), **Email** (SMTP, with STARTTLS + auth), **PagerDuty** (Events API v2), **Webhook** (generic JSON, Jinja2-templated body with `{{message}}`/`{{alert_name}}`/`{{severity}}`/`{{fired_at}}`), **Tracecat**.

### Security → Users / Auth

Local username/password login (JWT access token + httponly refresh-token cookie), Okta SAML 2.0 SSO (auto-provisioned users, role synced from IdP attributes on every login), and a **Change Password** flow for the current user. If both local auth and SAML are disabled, the app signs in automatically as the default admin (`/api/auth/auto-login`) rather than showing a login form with no way in.

### Security → Suite Integration

Two directions:
- **Inbound** (`/api/suite/token`, `/api/suite/register`, `/api/suite/regenerate`) — the token pktHub or another suite app uses to authenticate as a forwarded user via `X-Suite-Token`/`X-Suite-User`/`X-Suite-Role` headers.
- **Outbound** (`/api/integrations/*`) — named connections *to* sibling apps, e.g. a pktIPAM instance used for the internal-IP lookup in [IP Lookup](#ip-lookup-1) below. Multiple named instances per `app_name` are supported.

### Security → AI Assistant

Providers are grouped **Local / Self-Hosted (Private)** first, then **Cloud (Paid)** below — each with its own enable toggle instead of the old single provider radio. Local providers are tried first; the first enabled provider with valid config answers each chat question.

| Setting | Description |
|---|---|
| Ollama | Local models via a running Ollama server — base URL + model name |
| Local providers (+ Add) | Any number of additional OpenAI-compatible local endpoints (LM Studio, LocalAI, vLLM, etc.) — name, base URL, model, optional API key |
| `anthropic_key` / `anthropic_model` | API key + model (default `claude-opus-4-8`; also selectable: `claude-sonnet-5`, `claude-haiku-4-5-20251001`) |
| `openai_key` / `openai_model` | API key + model (default `gpt-4o`; also selectable: `gpt-4o-mini`, `o1`, or any model name typed manually) |

Both a "Say PONG" key test (`POST /api/ai/test`, Anthropic/OpenAI only) and the live chat panel are available.

### Security → SSL/TLS

Upload a PEM cert + key pair, or a PFX/PKCS#12 bundle + passphrase (converted server-side with `openssl`) — no manual file placement required. Status (installed/not, expiry, subject/issuer) is shown live. See [SSL / TLS](#ssl--tls) below.

### User Keys

Per-user API keys for **AbuseIPDB**, **IPQualityScore**, **ipinfo.io**, **ipapi.is**, and **MXToolbox** — scoped strictly to the logged-in user via `GET/PUT /api/user-api-keys/<provider>`, no shared/admin key, no cross-user visibility. Each provider can be individually enabled/disabled for the IP Lookup modal, and ipinfo.io/ipapi.is/MXToolbox further support per-field show/hide (e.g. hide "Company" but keep "Geolocation"). ipapi.is also supports a keyless free-tier toggle.

---

## Usage

### Analyzing a capture file

1. Open the app and log in.
2. Go to **Upload**, drag-and-drop (or browse for) a `.pcap`, `.pcapng`, or `.cap` file.
3. Click **Analyze (local)** to parse it entirely in the browser without touching the server, or **Analyze & Save** to also persist it to server storage first.
4. Results appear across seven tabs on the **Analyzer** page.
5. Optionally, click the floating **✦** button (bottom-right, any page) to ask the AI Assistant a question about the capture currently on screen.

### Analysis tabs

| Tab | Contents |
|---|---|
| **Summary** | Packet count, duration, rate, total size, capture window, protocol breakdown, top talkers (IP-linked) |
| **Anomalies** | Severity-tagged rule-based findings (RST rate, retransmissions, etc.) |
| **Flows** | All conversation flows and ports, with packet/byte counts |
| **TCP** | Health counters — RSTs, failed handshakes, retransmissions, zero-window events, problem streams |
| **UDP** | Total packets/bytes, per-flow packet/byte counts, one-sided-flow flagging |
| **DNS** | Query/answer/error counts, per-query answered status and RTT |
| **Threats** | Severity-tagged security findings with evidence lines (IP-linked) |

### IP Lookup

Click any underlined IP address anywhere in the Analyzer (top talkers, flows, TCP/UDP streams, threat evidence) to open a lookup modal:
- **Public IPs** — combined ipinfo.io geolocation/ASN/company/privacy-detection/abuse-contact/hosted-domains, ipapi.is geolocation/ASN/company/VPN-Tor-datacenter-abuser detection, AbuseIPDB abuse confidence score, and MXToolbox reverse-DNS/ASN/blacklist checks — using the logged-in user's own stored keys.
- **Private/RFC1918 IPs** — a pktIPAM inventory lookup (subnet, DHCP lease, DNS records, ARP sightings) over a configured Suite Integration, if one exists.

### Live feed (remote capture)

pktPCAP can receive a live pcapng stream from a remote host running `tshark` or Wireshark. The **Live Feeds** page has a command builder (session name, interface, BPF filter, duration) with tabs for all three collection methods (tshark/curl, Wireshark CLI, Wireshark UI) — see [Data Flow — Mode 2](#mode-2--remote-live-capture-live-feed) above for the full walkthrough.

---

## API Reference

All endpoints are served from the app root; interactive OpenAPI docs are available at `/api/docs` (Swagger) and `/api/redoc`.

### Auth (`/api/auth`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Local username/password login — returns a JWT access token, sets an httponly refresh-token cookie |
| `POST` | `/refresh` | Exchange the refresh-token cookie for a new access token |
| `POST` | `/logout` | Clear the refresh-token cookie |
| `GET` | `/config` | Which auth methods are available (no auth required — drives the Login page) |
| `POST` | `/auto-login` | Issue a session for the default admin when both local auth and SAML are disabled |
| `GET` | `/saml/metadata` | SP metadata XML (register this with the IdP) |
| `GET` | `/saml/login` | Redirect to the SAML IdP |
| `POST` | `/saml/callback` | SAML ACS callback — auto-provisions/role-syncs the user |

### Users (`/api/users`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/me` | Current user's own profile |
| `POST` | `/me/change-password` | Change the current user's own password |
| `GET` | `` | List all users (admin) |
| `POST` | `` | Create a user (admin) |
| `PATCH` | `/{id}` | Update a user (admin) |
| `PATCH` | `/{id}/reset-password` | Reset a user's password (admin) |
| `PATCH` | `/{id}/set-default-admin` | Mark a user as the fallback admin for auto-login (admin) |
| `DELETE` | `/{id}` | Delete a user (admin) |

### Settings (`/api/settings`)

| Method | Path | Description |
|---|---|---|
| `GET` | `` | Return current settings (secret keys hidden from non-admin callers) |
| `PUT` | `` | Save settings (admin) |
| `POST` | `/test-notification` | Send a real test message on one channel (admin) |

### System (`/api/system`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/info` | Version, install dir, port |
| `POST` | `/restart` | Graceful restart (exits the process; systemd's `Restart=on-failure` brings it back up) |
| `GET` / `POST` | `/port` | Read/update the listen port in `config.yaml` (takes effect on next restart) |
| `GET` | `/net-interfaces` | This host's own network interfaces (for the Wireshark-GUI tab only) |
| `GET` | `/ssl/status` | Installed cert status/expiry |
| `POST` | `/ssl/upload` | Install a PEM cert + key |
| `POST` | `/ssl/upload-pfx` | Install from a PFX/PKCS#12 bundle + passphrase |
| `DELETE` | `/ssl/cert` | Remove the installed cert/key |
| `GET` | `/backups` | List existing backup snapshots |
| `POST` | `/backups/run` | Run a backup snapshot immediately |
| `POST` | `/backups/restore/{snapshot_name}` | Restore directly from an on-server snapshot; optional `?files=pktpcap.db,config.yaml` to restore only some of it |
| `GET` | `/export` | Download a full backup bundle (`pktpcap.db` + `config.yaml`) as a `.tar.gz` |
| `POST` | `/import` | Upload a `.tar.gz` bundle to restore from; optional `files` form field restricts which files are restored |

### AI (`/api/ai`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/chat` | Send a question + optional capture context to the configured provider |
| `POST` | `/test` | Test a provider/key/model combination without saving it ("Say PONG") |

### Logs (`/api/logs`)

| Method | Path | Description |
|---|---|---|
| `GET` | `` | Query app logs (supports `?level=`, `?logger=`, `?limit=`, `?offset=`) |
| `GET` | `/stats` | Log count by level and logger |
| `DELETE` | `` | Clear all logs (admin only) |
| `POST` | `/level?level=DEBUG` | Change the live log level |

### Live Feed (mounted at `/api`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/capture/wrapper-config` | Unauthenticated — the fields the Wireshark wrapper script needs (enabled flags, feed token, default duration) |
| `POST` | `/feed/{name}` | Stream pcapng data into a named session (Bearer feed-token auth) |
| `GET` | `/feeds` | List active feed sessions |
| `GET` | `/feeds/{name}/download` | Download an active session's buffered bytes |
| `DELETE` | `/feeds/{name}` | Clear and remove an active session |

### Captures (`/api/captures`)

| Method | Path | Description |
|---|---|---|
| `GET` | `` | List persisted captures (DB-backed: status/source/size/created_at) |
| `POST` | `/upload` | Drag-and-drop upload from the Upload page |
| `GET` | `/{fname}/download` | Download a persisted capture |
| `DELETE` | `/{fname}` | Delete the file and its DB row |

### Suite Integration (`/api/suite`, `/api/integrations`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/suite/token` | Current inbound suite token, for display in Settings |
| `POST` | `/suite/register` | Called **by pktHub** to push/set this app's suite token |
| `POST` | `/suite/regenerate` | Generate a new inbound suite token (admin) |
| `GET` | `/suite/whoami` | Current session's identity, including suite-forwarded users |
| `GET` | `/integrations` | List outbound integrations to sibling apps |
| `POST` | `/integrations` | Create an outbound integration |
| `PUT` | `/integrations/{id}` | Update an outbound integration |
| `DELETE` | `/integrations/{id}` | Delete an outbound integration |
| `POST` | `/integrations/{id}/test` | Health-check a configured integration |

### User Keys (`/api/user-api-keys`)

| Method | Path | Description |
|---|---|---|
| `GET` | `` | Current user's own keys for `abuseipdb`, `ipqualityscore`, `ipinfo`, `ipapi_is`, `mxtoolbox` |
| `PUT` | `/{provider}` | Set (or clear) the current user's key for a provider |
| `PUT` | `/{provider}/enabled` | Toggle whether a provider's section shows in the IP Lookup modal |
| `PUT` | `/ipapi_is/free-tier` | Use ipapi.is's keyless free tier instead of a stored key |
| `PUT` | `/ipinfo/fields` / `/ipapi_is/fields` / `/mxtoolbox/fields` | Per-field show/hide preferences for that provider's modal section |
| `POST` | `/{provider}/test` | Validate a key against the real provider API using a harmless test IP |

### IP Info (`/api/ip-info`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/{ip}` | Combined ipinfo.io + ipapi.is + AbuseIPDB + MXToolbox lookup for a public IP, using the caller's own keys. 400 for private/loopback/reserved addresses |
| `GET` | `/internal/{ip}` | pktIPAM inventory lookup (subnet/lease/DNS/ARP) for a private IP, over a configured Suite Integration. 400 for public addresses |

### MXToolbox (`/api/mxtoolbox`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/lookup` | Generic passthrough to any MXToolbox `Lookup` command — body `{"command", "argument", "port"?}` |

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Public health check (used by pktHub / monitoring) |

---

## Project Structure

```
pktpcap/
├── app/                          ← Current FastAPI backend (used by install.sh / systemd)
│   ├── main.py                   ← FastAPI app, router registration, SPA static-file serving
│   ├── server.py                 ← uvicorn entry point (python -m app.server)
│   ├── config.py                 ← pydantic-settings — reads config.yaml + PKTPCAP_* env vars
│   ├── database.py                ← aiosqlite engine, migration runner, admin seeding
│   ├── dependencies.py           ← auth dependencies (JWT + suite-token), role guards
│   ├── logging_handler.py        ← SQLite log ring-buffer handler
│   ├── backup.py                 ← Scheduled/on-demand backup job
│   ├── api/                      ← One router module per feature: auth, users, settings,
│   │                                system, logs, integrations, suite, user_api_keys,
│   │                                ip_info, mxtoolbox, ai, captures, feeds
│   ├── auth/                     ← local.py (JWT/bcrypt), saml.py (Okta SSO)
│   ├── capture/                  ← auth.py (feed-token check), feed_sessions.py (in-memory
│   │                                buffers), storage.py (disk persistence), reconcile.py
│   │                                (background task reconciling captures vs disk)
│   └── integrations/              ← suite_client.py (outbound calls to sibling pkt* apps)
│
├── frontend/                     ← React 18 + Vite SPA (current)
│   ├── src/
│   │   ├── App.tsx               ← Routes: /, /live-feeds, /upload, /analyzer, /logs, /settings
│   │   ├── pages/                ← Dashboard, LiveFeeds, Upload, Analyzer, Logs, Settings, Login
│   │   ├── components/           ← Layout (sidebar nav), HelpButton, AiAssistant, IpLink, Pagination
│   │   ├── lib/pcap/              ← Client-side pcap/pcapng parser + rule-based analyzer (TypeScript)
│   │   ├── api/client.ts         ← Typed fetch wrapper for every backend endpoint
│   │   └── store/auth.tsx        ← JWT auth context (access token in memory, refresh via cookie)
│   ├── dist/                     ← Build output (gitignored) — this is what FastAPI serves
│   └── vite.config.ts            ← Dev server on :5176, proxies /api to :8765
│
├── migrations/                    ← Idempotent SQL, applied in order at startup
│   ├── 001_initial.sql            ← users, settings, app_logs, integrations, user_api_keys
│   └── 002_captures.sql           ← captures table
│
├── scripts/
│   ├── pktpcap                    ← Remote-capture wrapper script (source of truth) — copied to
│   │                                 <install_dir>/pktpcap by install.sh with __PORT__ substituted
│   └── verify_deploy.py           ← SSH into a deployed host and check service/port/health
│
├── install.sh                     ← Interactive Ubuntu Server install script (see Installation)
├── pktpcap.service                ← systemd unit template (placeholders substituted by install.sh)
├── config.example.yaml            ← Template for config.yaml (copied + filled in by install.sh)
├── requirements.txt                ← Python dependencies for app/ (current backend)
├── backup.py                      ← Standalone dev-machine checkout backup (2-rotation) — NOT
│                                     the in-app feature (that's app/backup.py)
│
├── service/                       ← LEGACY. The original Flask/Jinja app pktPCAP shipped as before
│                                     the 2026-07-26 rebuild. Left in the tree for reference only —
│                                     install.sh, pktpcap.service, and requirements.txt no longer
│                                     touch it, and it is not what a fresh install runs. Has its
│                                     own service/requirements.txt from before the rebuild.
│
├── ssl/                           ← SSL certs — GITIGNORED (place certs here, or upload via Settings)
│   └── .gitkeep
│
├── favicon.ico / favicon.svg / icon-*.png ← App icons
└── lockup-*.png / lockup.svg      ← Logo assets
```

pktPCAP is a **React 18 / Vite SPA** served by FastAPI (`app/main.py` mounts `frontend/dist` and falls back to `index.html` for client-side routing). Editing frontend source requires `npm run build` (or `npm run dev` against the `:5176` dev server, which proxies `/api` to `:8765`) — there's no live-reload of raw TS/TSX by the production server, unlike the old Flask/Jinja app.

---

## SSL / TLS

Install a certificate from **Settings → Security → SSL/TLS**: either a PEM cert + key pair, or a PFX/PKCS#12 bundle + passphrase (the server extracts it to PEM via `openssl` internally). Files are written to `ssl_dir` (default `<install_dir>/ssl`) as `server.crt` / `server.key`. Status, expiry, subject, and issuer are shown live via `GET /api/system/ssl/status`, which shells out to `openssl x509` to read the installed cert's metadata.

The `ssl/` directory is gitignored — never commit certificate material.

---

## Architecture Notes

**Path resolution:** `app/config.py` resolves a single `install_dir` (from `$PKTPCAP_INSTALL_DIR` → the directory the loaded `config.yaml` lives in → cwd) and every other on-disk path (`db_path`, `log_file`, `ssl_dir`, `storage_path`) defaults to somewhere under it — no source file hardcodes an absolute install path.

**Auth:** JWT access tokens (15 min expiry, `HS256`) + an httponly refresh-token cookie (7 days) for local login; `bcrypt` password hashing via `passlib`. A separate trust path exists for `X-Suite-Token`: if it matches the configured `suite_token`, the request is treated as the forwarded `X-Suite-User`/`X-Suite-Role` identity with no token of its own (`app/dependencies.py::get_current_user`).

**Feed sessions:** held entirely in the single worker process's memory (`app/capture/feed_sessions.py`) — this is why `workers` must stay `1` in `config.yaml`. A `ReconcileTask` runs in the background reconciling the `captures` DB table against what's actually on disk (catches crashes mid-write, manual file deletion, or `storage_path` changing under a running process).

**Backup scheduler:** `app/backup.py` starts a background task at boot that sleeps for `backup_interval_hours` and runs a snapshot whenever `auto_backup` is on; "Run Backup Now" (`POST /api/system/backups/run`) calls the same function directly, outside the schedule.

**Server restart:** `POST /api/system/restart` schedules `os._exit(1)` after a short delay and relies on the systemd unit's `Restart=on-failure` to bring the process back up — unlike the old Flask app, it does not self-`Popen` a replacement process (that pattern was found to occasionally leave an orphaned, systemd-untracked process squatting on the port).

**AI:** the floating `AiAssistant` component POSTs `{question, context}` to `/api/ai/chat`; the server resolves the first enabled provider (local/self-hosted first, then Anthropic or OpenAI) with a system prompt tuned for packet/capture troubleshooting and returns the answer. API keys never leave the host.

**pktHub / Suite integration:** inbound — the app accepts an `X-Suite-Token` header on every request; a matching token establishes the forwarded user/role with no separate login. Outbound — `app/integrations/suite_client.py` lets pktPCAP call a sibling app's own suite API (currently used to query pktIPAM for internal-IP lookups).

---

## Known Limitations

- **tshark interface field has no remote-host awareness.** The Live Feeds interface field's autocomplete suggestions come from `GET /api/system/net-interfaces` — pktPCAP's own host — which is only actually relevant to the Wireshark-GUI tab (where Wireshark SSHes into this same host). For the generic tshark/curl method, you must know and type the *remote* capture host's real interface name yourself (`tshark -D` on that host); the field is free-text and the mismatch is explained in its help text rather than fixed at the UI level.
- **Legacy `service/` tree.** The pre-rebuild Flask/Jinja app is still present in the repository for reference but is dead code — `install.sh`, `pktpcap.service`, and the root `requirements.txt` no longer reference it. It has its own separate `service/requirements.txt` and should not be edited expecting it to affect a running instance.
- **No upgrade path from the pre-rebuild database.** The FastAPI rebuild uses a fresh schema (`migrations/001_initial.sql`) — user accounts and settings from a pre-2026-07-26 Flask-based install are not carried forward automatically.
- **Single-worker constraint.** `workers` must stay at `1` because live feed sessions are held in one process's memory — this rules out horizontal scaling of the backend process without a redesign of feed storage.

If you're tracking a specific older bug list against this app, re-verify it against current code first — the 2026-07-26 FastAPI/React rebuild (`git log`: "Rebuild pktPCAP as FastAPI + React, matching the pkt* suite framework") explicitly rewrote the capture-persistence, Live Feeds copy/refresh, token-display, and tshark-allow-toggle screens as part of the same change, so bug reports filed against the pre-rebuild UI may no longer apply.

---

## Supported AI Models

| Provider | Models |
|---|---|
| Ollama / local (OpenAI-compatible) | Whatever's pulled/served on the configured endpoint — free-text model field |
| Anthropic | `claude-opus-4-8` (default), `claude-sonnet-5`, `claude-haiku-4-5-20251001` |
| OpenAI | `gpt-4o` (default), `gpt-4o-mini`, `o1`, and any model name entered manually |

---

## License

MIT
