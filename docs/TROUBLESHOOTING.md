# pktPCAP — Troubleshooting

Symptom, cause, and the command that proves which cause it is.

`<INSTALL_DIR>` is the install directory (`/opt/pktpcap` by default).

---

## Contents

- [The first five minutes](#the-first-five-minutes)
- [The service will not start](#the-service-will-not-start)
- [Workers must stay at 1](#workers-must-stay-at-1)
- [The service runs but nothing answers](#the-service-runs-but-nothing-answers)
- [The UI is blank, stale, or 404](#the-ui-is-blank-stale-or-404)
- [Login and accounts](#login-and-accounts)
- [Live feeds](#live-feeds)
- [Wireshark SSH remote capture](#wireshark-ssh-remote-capture)
- [Capture ownership and visibility](#capture-ownership-and-visibility)
- [Uploads and analysis](#uploads-and-analysis)
- [IP lookups show nothing](#ip-lookups-show-nothing)
- [A config change did not take effect](#a-config-change-did-not-take-effect)
- [TLS / HTTPS](#tls--https)
- [Backup, upgrades and uninstall](#backup-upgrades-and-uninstall)
- [What to capture before reporting a problem](#what-to-capture-before-reporting-a-problem)

---

## The first five minutes

```bash
sudo systemctl status pktpcap --no-pager
```

```bash
sudo journalctl -u pktpcap -n 100 --no-pager
```

```bash
sudo tail -n 100 <INSTALL_DIR>/logs/pktpcap.log
```

```bash
sudo ss -ltnp | grep 8765
```

```bash
curl -s http://127.0.0.1:8765/api/health
```

```bash
curl -s http://127.0.0.1:8765/api/feeds -H "Authorization: Bearer <JWT>"
```

| What you see | Go to |
|---|---|
| `inactive (dead)` or `failed` | [The service will not start](#the-service-will-not-start) |
| Running, nothing on 8765 | [The service runs but nothing answers](#the-service-runs-but-nothing-answers) |
| Health 200, UI blank or 404 | [The UI is blank, stale, or 404](#the-ui-is-blank-stale-or-404) |
| Feed connected, Analyzer empty | [Live feeds](#live-feeds) |

---

## The service will not start

```bash
sudo journalctl -u pktpcap -n 200 --no-pager
sudo tail -n 200 <INSTALL_DIR>/logs/pktpcap.log
```

Reproduce in the foreground:

```bash
sudo -u <service-user> \
  PKTPCAP_CONFIG=<INSTALL_DIR>/config.yaml \
  PKTPCAP_INSTALL_DIR=<INSTALL_DIR> \
  <INSTALL_DIR>/venv/bin/python -m app.server
```

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | venv missing packages, or built against a different Python | `<INSTALL_DIR>/venv/bin/pip install -r requirements.txt` |
| `yaml.scanner.ScannerError` | `config.yaml` is not valid YAML | `python3 -c "import yaml; yaml.safe_load(open('<INSTALL_DIR>/config.yaml'))"` |
| Complaint about `secret_key` / `credential_key` | Left at `CHANGE_ME_…` | `openssl rand -hex 32`; and `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `Address already in use` | Something else holds 8765 | `sudo ss -ltnp \| grep 8765` |
| `Permission denied` on `captures/` | Storage path not writable by the service user | `sudo chown -R <service-user>:<service-group> <INSTALL_DIR>` |
| Fernet `InvalidToken` | `credential_key` changed after secrets were stored | See [A config change did not take effect](#a-config-change-did-not-take-effect) |

`Restart=on-failure`, burst limit 5 in 60s. The unit sets
`AmbientCapabilities=CAP_NET_BIND_SERVICE` — only needed if the port is moved
below 1024; the default 8765 is unprivileged.

---

## Workers must stay at 1

**This is the constraint that explains the most confusing pktPCAP failures.**

Live feed sessions are held in the serving process's own memory. From the code:

> a multi-worker deployment would silently split ingest/list/download across
> separate processes and lose in-progress captures. Do not raise workers above 1
> without redesigning this to share state across processes.
> — [`app/capture/feed_sessions.py`](../app/capture/feed_sessions.py)

The word to note is **silently**. Nothing errors. Symptoms of `workers > 1`:

- A feed pushes successfully, but `GET /api/feeds` sometimes does not list it.
- A feed appears, then vanishes on refresh, then comes back.
- Download returns an empty or partial capture.
- Two admins see different feed lists.

```bash
grep -n "^workers" <INSTALL_DIR>/config.yaml
```

If that is not `1`, set it to `1` and restart before diagnosing anything else.

---

## The service runs but nothing answers

```bash
sudo ss -ltnp | grep 8765
curl -sv http://127.0.0.1:8765/api/health
```

`host:` and `port:` come from `config.yaml` at every process start — a port
change needs a restart, never a unit edit. Bound to `127.0.0.1` is loopback
only.

Note that moving the port breaks any configured remote pusher until it is
updated too.

---

## The UI is blank, stale, or 404

| Symptom | Cause | Fix |
|---|---|---|
| `{"detail":"Not Found"}` at the root | The frontend was never built | `cd frontend && npm install && npm run build`, then restart. Node.js 20.x LTS is a prerequisite `install.sh` does not install |
| Blank page, console 404s on `/assets/*` | `dist` stale or half-built | Rebuild, then hard-refresh |
| Old UI after an upgrade | Cached `index.html` pinning old bundles | Hard refresh (Ctrl/Cmd-Shift-R) |
| Every API call 401 | Session expired | See [Login and accounts](#login-and-accounts) |

---

## Login and accounts

bcrypt plus JWT. Roles `admin` / `analyst` / `viewer`. SAML is available.

| Symptom | Cause | Fix |
|---|---|---|
| 401 immediately after logging in | Clock skew invalidates the token's `exp` | `timedatectl`; fix NTP |
| Cannot delete someone else's capture | Ownership check | Only the owner, or an admin, can manage a capture |
| Locked out of every account | No admin session left | Reset the hash against SQLite using the app's own venv for bcrypt |

```bash
<INSTALL_DIR>/venv/bin/python -c "import bcrypt; print(bcrypt.hashpw(b'NewPassword1!', bcrypt.gensalt()).decode())"
```

---

## Live feeds

A feed is a live pcapng stream **pushed** to
`POST /api/feed/{name}` by tshark, the Wireshark SSH-remote-capture wrapper, or
anything else that can `curl`.

### Authentication

The push is machine-to-machine and does **not** use a user login. It carries a
bearer token checked against the `feed_token` setting.

That token is **read fresh from SQLite on every call, with no caching** — so
rotating it in Settings takes effect immediately, in both directions. Rotate it
and every existing pusher stops working at once.

| Response | Cause |
|---|---|
| 401 on push | Wrong or missing bearer token. Compare against the current `feed_token` in Settings |
| 401 right after a rotation | Expected — update the pusher |
| Push succeeds, nothing in the UI | Not an auth problem. Continue below |

### The 200 MB cap

Each session buffers up to **200 MB**, then sets a `truncated` flag and stops
growing.

```bash
curl -s http://127.0.0.1:8765/api/feeds -H "Authorization: Bearer <JWT>"
```

That returns each session's state — `connected`, `bytes_received`, `truncated`,
`last_seen`.

| Symptom | Cause |
|---|---|
| Feed shows connected, Analyzer shows nothing new | The buffer hit 200 MB and truncated. Start a new feed, or filter at the capture source so less is pushed |
| Capture smaller than expected | Same cap |
| `bytes_received` rising, Analyzer still empty | The stream is arriving but is not parseable as pcapng — check the pusher's output format |
| Feed disappears after a restart | **Feed sessions live in memory.** A restart loses every in-progress capture. This is by design |
| Feed list inconsistent between refreshes | `workers > 1` — see [Workers must stay at 1](#workers-must-stay-at-1) |

### Nothing arrives at all

Work outward from the pusher:

```bash
curl -i -X POST http://<APP_SERVER_IP>:8765/api/feed/test \
  -H "Authorization: Bearer <FEED_TOKEN>" \
  --data-binary @- < /dev/null
```

A non-401 response proves the network path and the token. After that it is the
pusher's own output.

---

## Wireshark SSH remote capture

| Symptom | Cause | Fix |
|---|---|---|
| Fails immediately | The **Allow** toggle is off | Enable it in Settings |
| Permission denied running dumpcap | The SSH user cannot capture | It needs to be root, or in the `wireshark` group with `dumpcap` setuid |
| Connects, no packets | Wrong interface, or a capture filter matching nothing | Test the same `dumpcap` command by hand over SSH |
| Works, but the capture is unowned | Expected — see below | |

`GET /api/capture/wrapper-config` returns the configuration the wrapper script
needs; if the script is misbehaving, compare what it has against that.

---

## Capture ownership and visibility

The ingest POST takes an optional `?owner=<user_id>`. It is **bookkeeping for
capture sharing, not a security boundary** — the push is authenticated by
`feed_token`, not by a user login.

| Situation | Result |
|---|---|
| Push includes `?owner=` | The resulting capture belongs to that user |
| Push omits it — including the Wireshark SSH wrapper, which has no pktPCAP user context at all | The capture stays **unowned and visible to everyone** |

| Symptom | Cause |
|---|---|
| "Why can everyone see my capture?" | It was pushed without an owner. That is the documented behaviour, not a leak introduced by sharing |
| A user cannot see a capture they made | It was pushed with a different `owner`, or they are looking at a shared/unshared filter |
| A user cannot delete a capture | Only the owner or an admin can manage it |

Because `owner` is a query parameter on an endpoint authenticated by a shared
token, do not treat it as an access control. Anything holding `feed_token` can
claim any owner id.

---

## Uploads and analysis

| Symptom | Cause |
|---|---|
| Large upload fails | Disk space under `captures/`, or a body-size limit in a reverse proxy in front of the app |
| Upload succeeds, analysis is empty | The file is not a format the analyzer reads — confirm it is pcap/pcapng |
| Analysis slow on a big file | Expected; parse cost scales with the capture |
| Captures disappearing | Retention on capture storage — check the setting before assuming deletion |
| Download gives a truncated file | The source feed was truncated at 200 MB |

---

## IP lookups show nothing

Private-address context comes from pktIPAM over a suite connection.

| Symptom | Cause |
|---|---|
| Private IPs show nothing useful | No enabled Suite Integration connection to pktIPAM |
| Connection health check fails on TLS | Suite calls verify the target's certificate — fix pktIPAM's cert, or clear verify-TLS for that connection |
| Public IP context missing | That path uses external lookups and needs egress |

None of this affects capture analysis itself — it only removes annotation.

---

## A config change did not take effect

**Wrong file.** Env vars beat `config.yaml` silently:

```bash
systemctl show pktpcap -p Environment
```

**Not restarted.** Nothing in `config.yaml` is re-read live, and restoring a
backed-up `config.yaml` never restarts the service.

**The setting is not in `config.yaml`.** That file holds startup and
infrastructure only — host, port, workers, secrets, paths, `storage_path`.
Capture storage and retention, notification channels, keys, SAML config, suite
integrations and per-user lookup API keys all live in **SQLite** and are managed
in the UI.

**`feed_token` is the exception that behaves differently.** It is read fresh
from SQLite on every push, so it needs no restart at all — it takes effect the
moment it is saved.

### `credential_key` changed or was lost

Stored secrets are Fernet-encrypted with it. Change it and they become
undecryptable — restore the old key or re-enter them. This is why
`uninstall.sh` keeps `config.yaml` by default.

---

## TLS / HTTPS

`ssl_dir` defaults to `<INSTALL_DIR>/ssl`.

| Symptom | Cause | Fix |
|---|---|---|
| Still HTTP after uploading a cert | Not restarted | Restart |
| Will not start after upload | Key does not match the cert | Compare `openssl x509 -noout -modulus -in cert.pem \| openssl md5` with `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| Pushers break after enabling HTTPS | They are still posting to the `http://` URL | Update every pusher and wrapper config |

```bash
curl -k https://127.0.0.1:8765/api/health
```

---

## Backup, upgrades and uninstall

Backups write timestamped `backup_*` directories; the settings live in SQLite.
A restored `config.yaml` never restarts the service. **Never copy a live SQLite
database with `cp`** — take `pktpcap.db`, `-wal` and `-shm` with the service
stopped.

Note that backups cover the database, not necessarily the capture files under
`captures/` — check what your backup settings include before relying on it.

Upgrade:

```bash
git pull
cd frontend && npm install && npm run build && cd ..
sudo systemctl restart pktpcap
```

**A restart destroys every in-progress feed.** Plan upgrades around live
captures.

Migrations are numbered `.sql` files run on startup and tracked in
`_migrations`. Re-running `install.sh` is better when a release drops or renames
a file; data is kept, and `PKTPCAP_REMOVE_EXISTING=1` (or `0`) answers its
prompt from a script.

Uninstall:

```bash
bash <INSTALL_DIR>/uninstall.sh
```

Data is kept by default — `config.yaml`, `pktpcap.db` and its `-wal`/`-shm`,
`logs/`, `backups/`, `ssl/` and **`captures/`**. `--purge` deletes them and is
not recoverable; `--dry-run` prints what would go; `--yes` skips prompts;
`--dir PATH` if the unit is already gone.

**Never mirror over an install directory with `rsync --delete`** — that destroys
the database and every stored capture.

---

## What to capture before reporting a problem

1. `VERSION`, and how it was installed.
2. **`workers` from `config.yaml`.** If it is not 1, that is very likely the
   answer.
3. `systemctl status pktpcap` plus the last 200 lines of **both** the journal and
   `logs/pktpcap.log`.
4. `config.yaml` **with `secret_key`, `credential_key` and passwords removed**.
5. For a feed problem: `GET /api/feeds` output showing `connected`,
   `bytes_received` and `truncated`.
6. The exact HTTP status the pusher receives from `POST /api/feed/{name}`.
7. For SSH remote capture: whether the same `dumpcap` command works by hand over
   SSH.

Never paste the real `feed_token`, other secrets, or an unredacted
`config.yaml`.
