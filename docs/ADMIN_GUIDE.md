# pktPCAP — Administrator Guide

Covers installing, configuring, and operating pktPCAP. For day-to-day usage (Upload, Analyzer, Live Feeds), see [USER_GUIDE.md](USER_GUIDE.md). See the [README](../README.md) for the full technical reference, including the Data Flow architecture diagrams.

## Installation

Requires Python 3.10+, Node.js/npm for the frontend build, and (for SAML) `libxml2-dev`/`libxmlsec1-dev`/`libxmlsec1-openssl`/`pkg-config`/`gcc` — `install.sh` installs the system packages.

```bash
git clone <repo-url>
cd pktpcap
bash install.sh
```

Prompts for install directory and port (default `8765`), handles the venv, `config.yaml`/`config.json`, DB setup, admin user, frontend build, and systemd service. Log in with the printed admin credentials.

## First-time setup checklist

1. **Change the admin password.**
2. **Decide your capture delivery mode(s)**: local file upload needs no server-side setup at all (parsing is entirely client-side); live feeds need either a remote `tshark`/`curl` pipe or Wireshark's own SSH Remote Capture pointed at this host — see Live Feed setup below.
3. **Enable an AI provider** (Settings → Security → AI Assistant) if you want the floating assistant to work — local/self-hosted (Ollama, or any OpenAI-compatible endpoint), Anthropic, or OpenAI; each has its own enable toggle and local providers are tried first.
4. **Set up a Suite Integration connection to pktIPAM** if you want private/RFC1918 IPs in the Analyzer to resolve to real inventory data instead of just showing as plain addresses.
5. **Configure alert notification channels.**
6. **Set up backups** and confirm a manual run succeeds.
7. **Create accounts** for your team.

## Users & roles

`admin`, `analyst`, `viewer` — Settings, log clearing, and admin routes are enforced server-side, not just hidden in the UI. Manage accounts at Settings → Users: create/edit/delete, reset password, and designate a default admin.

### Okta SAML SSO

`python3-saml`-based, with auto-provisioning and role-sync from IdP attributes on login. If both local auth and SAML are disabled, the login page is skipped and everyone auto-signs in as the default admin (`/api/auth/auto-login`) — only appropriate on a trusted, access-controlled network.

## Live Feed setup

Two collection methods, configured on the **Live Feeds** page:

### tshark / curl pipe

Any remote host running `tshark` can stream pcapng directly to `/api/feed/<name>` over HTTP. Build the command from the Live Feeds page's command builder (session name, interface, BPF filter, duration).

### Wireshark GUI SSH Remote Capture

Uses Wireshark's built-in SSH Remote Capture interface type against a small wrapper script (`scripts/pktpcap`, installed at `<install_dir>/pktpcap`) that tees the capture — one copy to Wireshark over the SSH pipe, one POSTed to pktPCAP's own feed endpoint.

1. Enable it: Live Feeds → **Wireshark SSH Remote Capture** tab → toggle **Allow Wireshark SSH Remote Capture** on (admin only).
2. In Wireshark: Capture → Options → Manage Interfaces → Remote Interfaces (or the SSH remote capture interface type), and set SSH host/user/auth, Remote Capture Command = `<install_dir>/pktpcap`, and the interface name on this host.
3. Running `dumpcap` over SSH needs `root` or a user in the `wireshark` group with `dumpcap` setuid permissions on this host, same as the tshark method.
4. If the toggle is off, the wrapper exits with an error rather than silently failing.

A live Wireshark session also shows up as a normal entry in **Active Feed Sessions** in the UI — click Analyze to pull it into the standard rule-based/AI analysis.

### Feed session lifecycle

A session is `connected` while data is flowing. If a Captures storage path is configured, bytes are written to disk on disconnect and a `captures` row is created (`status=saved`); otherwise the buffer stays in memory until downloaded/analyzed, deleted, or a restart. **Buffer limit is 200 MB per named session** — exceeding it sets a `truncated` flag and discards further bytes. Monitor active sessions via `GET /api/feeds`.

## Persisted captures

Uploaded or feed-saved `.pcapng` files are tracked in a `captures` DB table (status: saving/saved/failed/missing) — not just a directory listing, so the UI knows the real state of each file.

Each capture is attributed to the user who created it (`created_by`) and has a `shared` flag: private to the owner by default, toggleable by the owner or any admin so other users can see and analyze it (labeled "Shared by `<username>`" in their list). Captures with no owner — e.g. a Wireshark SSH remote-capture push, which has no pktPCAP user context — stay visible to everyone regardless of `shared`, matching pre-sharing-feature behavior. Delete/share permissions follow the same owner-or-admin rule server-side, not just in the UI.

## Notification channels

Slack, Email (SMTP), PagerDuty, generic Webhook, Tracecat — configured under Settings, each independently enabled with a built-in **Send Test** button that performs a real dispatch.

## SSL/TLS

Upload a PEM cert+key or a PFX/PKCS#12 bundle from Settings — status/expiry is shown, no manual file placement required.

## Suite Integration

- **Inbound**: pktPCAP accepts an `X-Suite-Token` header from pktHub (or another suite app) for proxied auth, no separate login needed when embedded.
- **Outbound**: named connections to sibling `pkt*` apps — currently used for the pktIPAM internal-IP lookup in the Analyzer.

## Backup & Restore

Configure schedule and rotation in Settings — snapshots the SQLite DB and config on an interval, with rotation; **Run Backup Now** for an immediate snapshot.

**Restoring:**
- Every listed snapshot has a **Restore…** link — restores directly from that on-server snapshot, no download/upload needed. Expanding it shows a checkbox per file present, so you can restore just one piece instead of everything.
- A full bundle can also be exported/imported as a `.tar.gz` (added alongside the snapshot-restore feature — earlier builds only had on-server snapshots with no download/upload path at all), with the same per-file selection on upload.
- Restoring a config change needs a service restart to take effect.

## Known limitations

See the README's [Known Limitations](../README.md#known-limitations) section for the current list — check there before assuming something's broken versus a documented gap.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service won't start | `journalctl -u pktpcap -n 50`; check config paths |
| Live feed shows connected but no data in Analyzer | Confirm the buffer hasn't hit the 200MB truncation limit; check `GET /api/feeds` for session state |
| Wireshark SSH Remote Capture fails immediately | Confirm the Allow toggle is on and the SSH user has `dumpcap` permissions (root or `wireshark` group with setuid) |
| Private IP lookups show nothing useful | Confirm a Suite Integration connection to pktIPAM exists and is enabled |
| A restored config didn't take effect | Restart the service — restoring never does this automatically |

## Upgrading

Pull the latest code, rebuild the frontend if you build manually, then restart the service. Migrations run automatically on startup.
