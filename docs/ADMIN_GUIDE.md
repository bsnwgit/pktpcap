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
4. **Set up a Suite Integration connection to pktIPAM** if you want private/RFC1918 IPs in the Analyzer to resolve to real inventory data instead of just showing as plain addresses.
5. **Configure alert notification channels.**
6. **Set up backups** and confirm a manual run succeeds.
7. **Create accounts** for your team.

## Finding your way around Settings

Settings has a section bar above its tab bar with two buttons:

- **pktPCAP** — Captures and Capture Ingest, this app's own settings.

The tab bar shows one section's tabs at a time, so if a tab you're looking for isn't listed, switch sections. These tabs previously shared one long row split by a thin divider. Deep links (`/settings?tab=ingest`, the links from alert emails, and so on) still land on the right tab — the section follows automatically.

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

A live Wireshark session also shows up as a normal entry in **Active Feed Sessions** in the UI — click Analyze to pull it into the standard rule-based analysis.

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

### Managed mode

pktHub can put this app into **Managed mode**, which stops people reaching its UI directly and sends them to the hub instead. Nothing needs configuring here: the hub sends the address to redirect to when it applies the lock, because that address is built from the hub's own Base URL and this app's id in the hub's registry, and neither is visible from this side.

The lock redirects rather than shuts down. Anything carrying a valid suite token passes through untouched, as do `/api/health`, `/api/suite/`, `/api/auth/` and the paths a hub-rendered page needs, so pktHub itself keeps working normally.

**It expires on its own.** Every call from pktHub refreshes a heartbeat and the lock releases after five minutes without one, so it does not depend on the hub coming back — a lock only pktHub could lift would strand this app exactly when pktHub is what broke. `GET /api/suite/mode` reports the current state without authentication.

For an install with no pktHub in front of it, the address can be set directly with `PATCH /api/suite/hub-redirect-url` (admin session; http/https only, since every visitor follows it while the lock is on). pktHub overwrites it whenever it applies a lock.

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

## Resonance (embedded assistant)

Settings → Resonance (admin only). Adds an assistant launcher to the bottom corner of every page. The assistant itself runs on the resonance server; pktPCAP only decides who may open it.

**Setting it up.** Paste the **interface server** address — not resonance's admin portal, which answers on a different address and serves `embed.js` too, so it looks right until the session call returns "not found" — then the key you were issued. Choose which roles may use it, press **Test Connection**, and only then switch **Enabled** on. Test Connection works whether or not the feature is enabled; always prove a key before putting the widget in front of users. Every field ships blank, so a fresh install shows nothing until it is pointed at a resonance server of its own.

Two things have to line up on the resonance side, and both fail silently when they don't:

- **This install's origin** must be on the key's allow-list. The exact string is shown ready to copy on the same page. Behind a reverse proxy, fill in **pktPCAP's own address** yourself — what the app detects is the internal address, not the one users type.
- **Speakers Name** must be on for the key. Without it resonance records nothing, so there is no trace of who asked what.

**Reachability, twice over.**

- Resonance must be reachable **from the browser**, over HTTPS, with a certificate those browsers already trust. An untrusted certificate produces an empty widget and nothing in the console to explain it.
- pktPCAP also calls resonance **server to server**, so this host must resolve resonance's name and trust its certificate — the browser doing both is not enough. Python verifies against its own bundled roots rather than the system store, so a certificate signed by an internal CA is trusted by every browser on the network and still rejected here. Point **CA bundle** at the system store instead (`/etc/ssl/certs/ca-certificates.crt` on Debian and Ubuntu).

**What it can reach.** The capture catalogue — which captures exist, what each was called, its size, source, owner and state — the catalogue summary, and pktPCAP's own diagnostic log. Every call is made by pktPCAP's own page on the session of whoever is signed in, so it reaches only what that person could already open. `/.well-known/resonance.json` lists exactly what is on offer.

**It cannot read a capture.** No packet, header or payload is returned by any operation. The assistant sees the catalogue, never the contents; reading a capture stays a deliberate act a person performs by downloading it.

**There is no write half on this app, deliberately.** pktPCAP's only state changes are deleting a capture, sharing one beyond its owner, and accepting an upload — none of which belongs to an assistant — and there is no alert engine here to acknowledge. So the role switch below has two positions rather than three, instead of offering a *Read and write* level that would do nothing.

Documentation is published separately at `GET /api/resonance/docs`, to a suite token or an admin session — the guides shipped with the running version, so pointing resonance at it keeps the assistant's knowledge in step with the installed release.

**Who may open it.** Set per role: *No access* hides the launcher entirely, *Allowed* shows it. Nothing on this page grants a right the role does not already have.

**Credentials.** pktPCAP never sends a login to resonance. It vouches for whoever is signed in and gets back a short-lived, single-use code the browser spends on opening the panel. The key is encrypted at rest and never reaches the browser.

**If it never appears.** Diagnostics reports how many users could not load the widget in the last week; the usual causes are an ad blocker, a wrong server address, or resonance being unreachable. Repeated failures pause the integration for a few minutes rather than hammering resonance — the panel says so while it is paused, and a successful Test Connection clears it.

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

Re-running `install.sh` also works, and is the better route when a release drops
or renames a file: it detects the existing install, reports the version it
found, and offers to uninstall it first so no stale module is left importable.
Your data is kept either way, and the port you enter at the prompt is applied to
the existing `config.yaml` without touching another line of it. Set
`PKTPCAP_REMOVE_EXISTING=1` (or `0`) to answer that prompt from a script;
non-interactive runs upgrade in place.

## Uninstalling

`install.sh` copies `uninstall.sh` into the install directory, so it is on the
host without the repo:

```bash
bash /opt/pktpcap/uninstall.sh
```

It reads the install directory from the systemd unit, stops and removes the
service, and deletes the application code and the virtualenv. **Data is kept by
default** — `config.yaml` (which holds the JWT secret and the credential
encryption key), `pktpcap.db` and its `-wal`/`-shm`, `logs/`, `backups/` and
anything uploaded under `ssl/`, `captures/`. It asks separately before removing
those, and that prompt defaults to no.

| Flag | Effect |
|---|---|
| *(none)* | Remove the service, the code and the venv; keep data. Prompts first. |
| `--purge` | Also delete the config, database, logs, backups and TLS material. Not recoverable. |
| `--dry-run` | Print what would be removed; change nothing. |
| `--yes` | Skip the prompts — required for a non-interactive run. |
| `--dir PATH` | Install directory, if the unit file is already gone. |

Re-running `install.sh` afterwards against the same directory picks the kept
data back up, so the admin password and every setting survive an uninstall that
was not a `--purge`.

An install directory that is itself a git checkout (an in-place install) is
detected, and its source tree is never deleted — only the unit and the venv go.

