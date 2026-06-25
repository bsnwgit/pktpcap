# Packet Capture Analyzer — Project Context

## Overview
Standalone Python Flask web service that parses `.pcap`/`.pcapng` files in the browser, analyzes them with AI (Anthropic or OpenAI), and runs locally as a persistent app — same pattern as Maverik and other apps in `C:\apps`.

**Current status (as of 2026-06-23):** App is DEPLOYED and running at http://localhost:8765. Git repos are live on GitHub and GitLab. API key needs to be added at /settings for AI analysis to work.

---

## Folder Layout

```
C:\Users\robert.barnett\My Drive\Documents\Claude\Projects\Packet Analyzer\
├── service/                        ← Runtime source (canonical copy)
│   ├── server.py                   ← Flask server (main entry point)
│   ├── requirements.txt            ← flask, anthropic, openai
│   ├── config.json                 ← Runtime config (API keys, port) — GITIGNORED
│   ├── static/
│   │   └── index.html              ← Full SPA (~1969 lines)
│   └── templates/
│       └── settings.html           ← Settings UI
├── deploy-to-apps.bat              ← Copies service/ → C:\apps\pktpcap\
├── git-setup-and-push.bat          ← Full git init + push to GitHub + GitLab
├── .gitignore                      ← Excludes config.json, screenshots/, *.pcapng
├── PROJECT_CONTEXT.md              ← This file
├── pktpcap.html            ← Original standalone artifact (pre-Flask)
├── screenshots/                    ← Tab screenshots (GITIGNORED)
│   └── capture.png                 ← Last captured screenshot
└── test-cap.pcapng                 ← Test capture file (1.6 MB) — GITIGNORED
                                       (also at C:\Users\robert.barnett\Downloads\test-cap.pcapng)
```

### Deployment target (same pattern as Maverik)
```
C:\apps\pktpcap\
├── server.py
├── requirements.txt
├── start.bat                       ← Launch script (cd here, pip install, python server.py)
├── config.json                     ← Pre-existing, needs API key added via /settings
├── static/index.html
├── templates/settings.html
├── screenshot.ps1                  ← PS script: captures Chrome window → screenshots/capture.png
└── screenshot-named.ps1            ← PS script: accepts -FileName param for named captures
```

---

## How to Run

**Development (from project folder):**
```
cd "C:\Users\robert.barnett\My Drive\Documents\Claude\Projects\Packet Analyzer\service"
pip install -r requirements.txt
python server.py
```

**Deployed (currently running):**
```
C:\apps\pktpcap\start.bat
```

Opens at: http://localhost:8765
Settings: http://localhost:8765/settings

**To redeploy after code changes:** run `deploy-to-apps.bat`

---

## App UI — Tabs

After loading a .pcap/.pcapng file and clicking "Run Auto-Triage" or "Analyze Captures", the results view shows these tabs:

| Tab | Description |
|-----|-------------|
| Summary | Packet count, duration, data size, protocol distribution, top talkers |
| Anomalies (N) | HIGH-severity findings (RST rate, retransmissions, etc.) |
| Flows (N) | All conversation flows with packet/byte counts, stream viewer |
| TCP (N) | Health counters (RST, retransmissions, zero-window) + problem streams |
| UDP (N) | UDP stats (large datagrams, one-sided flows, high-rate flows) |
| DNS | DNS query summary |
| Threats (N) | Security findings (port scans, cleartext HTTP, credential risk, etc.) |

Tabs are scrollable via `‹` / `›` arrows — not all visible at once.

### Three Analysis Modes
- **Specific Issue** — user describes a known problem, AI focuses diagnosis on it
- **Auto-Triage** — AI scans for anything suspicious and reports findings
- **Security Review** — security-focused analysis

---

## Test Run Results (test-cap.pcapng, 1.57 MB)

Ran with Auto-Triage mode. Parser works fully without API key — AI assistant panel requires key.

| Metric | Value |
|--------|-------|
| Packets | 4,168 |
| Duration | 50.987s (81.7 pps) |
| Data | 1.43 MB |
| TCP | 2,338 (56.1%) |
| UDP | 1,025 (24.6%) |
| VLAN | 571 (13.7%) |
| Top talker | 10.1.157.141 (429.7 KB) |

**Anomalies detected (no AI needed — rule-based):**
- HIGH: High TCP RST Rate — 38 RST packets, abrupt connection terminations across multiple streams
- HIGH: Excessive Retransmissions — 663 retransmissions, significant packet loss on the path

**Threats detected:**
- MEDIUM Reconnaissance: Possible Port Scan — 216.239.32.223 hit 38 unique host:port combos
- MEDIUM Credential Risk: Cleartext HTTP — 8 packets on port 80, credentials/data in plaintext

---

## server.py — Architecture

`BASE = Path(__file__).parent` — all paths resolve relative to server.py's location, so the app works correctly from both `service/` and `C:\apps\pktpcap\`.

### API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Serves static/index.html |
| GET | `/settings` | Renders settings.html template |
| GET | `/api/settings` | Returns config (API keys masked after first 8 chars) |
| POST | `/api/settings` | Saves config; skips overwriting keys if value contains `•` |
| POST | `/api/ai` | Proxies prompt+data to Anthropic or OpenAI |
| POST | `/api/ai/test` | Tests API key with "Say PONG" request |
| POST | `/api/restart` | Spawns new process then `os._exit(0)` after 0.8s |
| GET | `/api/startup` | Returns `{enabled: bool}` — checks Startup folder for .bat |
| POST | `/api/startup` | Writes/removes `%APPDATA%\...\Startup\pktpcap.bat` |
| POST | `/api/save-image` | Saves base64 dataUrl to screenshots/ — **NOTE: saves to C:\apps\screenshots\ not C:\apps\pktpcap\screenshots\ — path bug, BASE.parent issue to investigate** |
| POST | `/api/screenshot` | PowerShell PrintWindow capture (unreliable, not used) |

### Key Implementation Details

**API key masking:** GET returns keys as `sk-ant-api0•••••••...`. POST only overwrites if the submitted value contains no `•` character.

**Server restart:** `subprocess.Popen([sys.executable] + sys.argv)` spawns a new instance, then `os._exit(0)` after 0.8s. Browser reconnects automatically.

**Windows Startup toggle:** Writes `pythonw "C:\apps\pktpcap\server.py"` to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\pktpcap.bat`. Uses `pythonw` (no console window).

**AI proxy (`/api/ai`):** `index.html` calls `localAsk()` which POSTs to `/api/ai`. This replaced the original `window.cowork.askClaude()` call so the app works standalone without Cowork.

---

## config.json Schema

```json
{
  "port": 8765,
  "provider": "anthropic",
  "anthropic_key": "sk-ant-...",
  "anthropic_model": "claude-opus-4-8",
  "openai_key": "sk-...",
  "openai_model": "gpt-4o"
}
```

Default model: `claude-opus-4-8`. Also supports `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`.

---

## index.html — Key Sections

- **`localAsk(prompt, dataArray)`** — added just before `</script>`. POSTs to `/api/ai`, mirrors the old `window.cowork.askClaude()` signature.
- **Settings link** — `<a href="/settings">⚙ Settings</a>` in the page header, outside all conditional divs, always visible.
- All `window.cowork.askClaude(` calls replaced with `localAsk(`.
- Tab selector: `[data-tab], .tab-btn, button[class*="tab"], [role="tab"]` — works for JS tab navigation.
- Main content container: `.main` (left panel with tab data).

---

## Screenshot Capture — Current Status

### What Works
- **`C:\apps\pktpcap\screenshot.ps1`** — captures Chrome window by title matching "localhost|Packet|8765" using `SetForegroundWindow` + `CopyFromScreen`. Saves to `C:\apps\pktpcap\screenshots\capture.png`.
- **`C:\apps\pktpcap\screenshot-named.ps1`** — same but accepts `-FileName` parameter for named output files.
- **`/api/save-image`** endpoint responds correctly to POST with `{dataUrl, filename}`. **Saves to `C:\apps\screenshots\` (not `C:\apps\pktpcap\screenshots\`) — path bug.**

### Known Problems
- **Multi-monitor issue:** The PS scripts find Chrome at position (1920,0) — the user's second monitor. When Claude in Chrome controls a tab and JS clicks navigate tabs, the PS script screenshots the WRONG Chrome window (user's window on monitor 2, not Claude's controlled tab).
- **html2canvas:** Times out on `document.body` (too many DOM nodes at 4,168 packets). `.main` element (left panel only) is the right target — this approach was in progress but not completed.
- The correct approach for programmatic tab screenshots: use `html2canvas` on `.main` in the Claude-controlled Chrome tab, then POST to `/api/save-image`. Needs the `C:\apps\screenshots\` path bug fixed first.

### Pending Screenshot Work
To capture all 7 tabs as named PNGs:
1. Fix the `/api/save-image` path bug so it saves to `C:\apps\pktpcap\screenshots\`
2. Inject html2canvas (`https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js`) via `javascript_tool`
3. For each tab: click via JS → wait 600ms → `html2canvas(document.querySelector('.main'))` → POST to `/api/save-image`

---

## Git Workflow

**IMPORTANT:** Never push directly to `main`. All changes go to a feature branch. Open PRs on both repos for user approval before merging.

| Remote | URL |
|--------|-----|
| github | git@github.com:bsnwgit/pktpcap.git |
| gitlab | git@gitlab.com:robert.barnett/pktpcap.git |

**PR links (template):**
- GitHub: `https://github.com/bsnwgit/pktpcap/compare/<branch>`
- GitLab: `https://gitlab.com/robert.barnett/pktpcap/-/merge_requests/new?merge_request[source_branch]=<branch>`

**Git push notes:**
- Bash sandbox has no SSH outbound access — must use Desktop Commander (`shell: cmd`) which uses the user's Windows SSH keys.
- Google Drive sync can cause `.git/config.lock` issues — use Desktop Commander `cmd` shell with `rmdir /s /q .git` if needed.
- GitHub may reject with "fetch first" if remote has commits — use `--force` for initial push.
- GitLab has branch protection on main — do `git pull gitlab main --allow-unrelated-histories` before pushing.

---

## Pending / Known Issues

| Item | Status | Notes |
|------|--------|-------|
| Add API key to deployed app | Pending | Go to http://localhost:8765/settings and enter Anthropic key |
| Redeploy after code changes | Pending | Run `deploy-to-apps.bat` to sync service/ → C:\apps\pktpcap\ |
| Fix /api/save-image path | Bug | Saves to C:\apps\screenshots\ instead of C:\apps\pktpcap\screenshots\ |
| Tab screenshot capture | In Progress | html2canvas on .main element + /api/save-image. See screenshot section above. |
| Confluence KB article | Blocked | Article drafted and approved. `createConfluencePage` returns 404 — Atlassian connector likely lacks `write:confluence-content` scope. Needs reconnection with write permissions. |

---

## Confluence Article (drafted, not yet published)

**Title:** How to - Packet Capture Analyzer (PktPCAP)
**Space:** SEC (Security Confluence space)
**Parent page ID:** 631406680 (SEC space homepage)
**Cloud ID:** d08da9e7-83db-4179-add1-b58cf5dcbe5c
**Space ID:** 631406623

Full article content is in previous conversation context. Needs Atlassian connector reconnected with write scope to publish.

---

## Tech Stack

- Python 3, Flask ≥ 3.0
- `anthropic` ≥ 0.40, `openai` ≥ 1.50
- Vanilla JS (no framework) in index.html
- Single-file SPA served from Flask static folder
- Jinja2 templates for settings.html
