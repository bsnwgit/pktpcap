# Packet Capture Analyzer — Project Context

## Overview
Standalone Python Flask web service that parses `.pcap`/`.pcapng` files in the browser, analyzes them with AI (Anthropic or OpenAI), and runs locally as a persistent app — same pattern as Maverik and other apps in `C:\apps`.

---

## Folder Layout

```
C:\Users\user\My Drive\Documents\Claude\Projects\Packet Analyzer\
├── service/                        ← Runtime source (canonical copy)
│   ├── server.py                   ← Flask server (main entry point)
│   ├── requirements.txt            ← flask, anthropic, openai
│   ├── config.json                 ← Runtime config (API keys, port) — GITIGNORED
│   ├── static/
│   │   └── index.html              ← Full SPA (~1969 lines)
│   └── templates/
│       └── settings.html           ← Settings UI
├── deploy-to-apps.bat              ← Copies service/ → C:\apps\packet-analyzer\
├── git-setup-and-push.bat          ← Full git init + push to GitHub + GitLab
├── .gitignore                      ← Excludes config.json, screenshots/, *.pcapng
├── PROJECT_CONTEXT.md              ← This file
├── packet-analyzer.html            ← Original standalone artifact (pre-Flask)
└── test-cap.pcapng                 ← Test capture file (1.6 MB) — GITIGNORED
```

### Deployment target (same pattern as Maverik)
```
C:\apps\packet-analyzer\
├── server.py
├── requirements.txt
├── start.bat                       ← Launch script (cd here, pip install, python server.py)
├── config.json                     ← Created on first run
├── static/index.html
└── templates/settings.html
```

---

## How to Run

**Development (from project folder):**
```
cd "C:\Users\user\My Drive\Documents\Claude\Projects\Packet Analyzer\service"
pip install -r requirements.txt
python server.py
```

**Deployed (after running deploy-to-apps.bat):**
```
C:\apps\packet-analyzer\start.bat
```

Opens at: http://localhost:8765  
Settings: http://localhost:8765/settings

---

## server.py — Architecture

`BASE = Path(__file__).parent` — all paths resolve relative to server.py's location, so the app works correctly from both `service/` and `C:\apps\packet-analyzer\`.

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
| POST | `/api/startup` | Writes/removes `%APPDATA%\...\Startup\packet-analyzer.bat` |
| POST | `/api/save-image` | Saves base64 dataUrl to screenshots/ (unused) |
| POST | `/api/screenshot` | PowerShell PrintWindow capture (abandoned, doesn't work reliably) |

### Key Implementation Details

**API key masking:** GET returns keys as `sk-ant-api0•••••••...`. POST only overwrites if the submitted value contains no `•` character.

**Server restart:** `subprocess.Popen([sys.executable] + sys.argv)` spawns a new instance, then `os._exit(0)` after 0.8s. Browser reconnects automatically.

**Windows Startup toggle:** Writes `pythonw "C:\apps\packet-analyzer\server.py"` to `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\packet-analyzer.bat`. Uses `pythonw` (no console window).

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

---

## Git Remotes

| Remote | URL |
|--------|-----|
| github | git@github.com:bsnwgit/pktanalyzer.git |
| gitlab | git@gitlab.com:example/pktanalyzer.git |

**To push:** Run `git-setup-and-push.bat` from the project folder (handles broken .git cleanup, init, commit, push to both remotes). Requires Windows SSH keys for GitHub/GitLab.

---

## Pending / Known Issues

| Item | Status | Notes |
|------|--------|-------|
| Deploy to C:\apps | Pending | Run `deploy-to-apps.bat` |
| Git push | Pending | Run `git-setup-and-push.bat` or use Desktop Commander |
| Confluence KB article | Blocked | Article drafted and approved. `createConfluencePage` returns 404 — Atlassian connector likely lacks `write:confluence-content` scope. Needs reconnection with write permissions. |
| Screenshot saving | Abandoned | html2canvas timeout, SetForegroundWindow captured wrong window, PrintWindow also captured wrong window. User said "nevermind." |
| Update startup .bat path | Auto | Settings page writes `BASE / "server.py"` — auto-correct once running from C:\apps |

---

## Confluence Article (drafted, not yet published)

**Title:** How to - Packet Capture Analyzer (PktAnalyzer)  
**Space:** SEC (Security Confluence space)  
**Parent page ID:** 631406680 (SEC space homepage)  
**Cloud ID:** d08da9e7-83db-4179-add1-b58cf5dcbe5c  
**Space ID:** 631406623  

Full article content is in the previous conversation context. Needs Atlassian connector reconnected with write scope to publish.

---

## Tech Stack

- Python 3, Flask ≥ 3.0
- `anthropic` ≥ 0.40, `openai` ≥ 1.50
- Vanilla JS (no framework) in index.html
- Single-file SPA served from Flask static folder
- Jinja2 templates for settings.html
