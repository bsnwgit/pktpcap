"""
/api/system/* — version info, SSL, backups, and admin diagnostics.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import aiosqlite

from app.config import get_settings
from app.dependencies import AdminUser, CurrentUser
from app.backup import run_backup_sync, list_backups_sync, _read_backup_settings_sync
from app.version import get_version

router = APIRouter()


async def _delayed_restart(delay: float = 1.5) -> None:
    """Wait briefly, then exit so systemd restarts the service (Restart=on-failure)."""
    await asyncio.sleep(delay)
    os._exit(1)


def _config_file_path() -> Path:
    """Locate the on-disk config.yaml — same candidates app/config.py checks."""
    cfg = get_settings()
    for candidate in [Path("config.yaml"), Path(cfg.install_dir) / "config.yaml"]:
        if candidate.exists():
            return candidate
    raise HTTPException(500, "config.yaml not found")


@router.get("/info")
async def system_info(user: CurrentUser) -> dict:
    """Version/about info shown on the Settings → System tab."""
    cfg = get_settings()
    return {
        "app_name": "pktPCAP",
        "version": get_version(),
        "install_dir": cfg.install_dir,
        "port": cfg.port,
        "github": "https://github.com/bsnwgit/pktpcap",
        "license": "PolyForm Noncommercial 1.0.0",
        "developer": "Robert Barnett",
        "contact": "inquiry@barsoftnetware.com",
    }


class BrowseEntry(BaseModel):
    name: str
    path: str
    is_dir: bool


class BrowseResult(BaseModel):
    path: str
    parent: Optional[str]
    entries: list[BrowseEntry]


@router.get("/browse-fs", response_model=BrowseResult)
async def browse_fs(user: AdminUser, path: str = ""):
    """List a directory on THIS pktPCAP server's filesystem. Backs the
    Remote Command file picker in the Wireshark SSH Remote Capture builder
    (Live Feeds page) — that command path has to point at a real
    executable on this host, so browsing beats typing it blind. Admin-only,
    same trust boundary as SSL cert upload / restart / backup export —
    an admin already has full server access via SSH, so no extra
    sandboxing beyond the role gate.
    """
    settings = get_settings()
    base = Path(path) if path else Path(settings.install_dir)
    try:
        base = base.resolve()
    except OSError:
        raise HTTPException(status_code=400, detail="Invalid path")
    # A caller may pass a file path (e.g. re-opening the browser on the
    # Remote Command field's current value, which points at an executable,
    # not a folder) — browse its containing directory instead of 404ing.
    if base.exists() and base.is_file():
        base = base.parent
    # A typed-but-not-yet-real path (e.g. a fresh install with no binary at
    # that path yet) shouldn't dead-end the picker — fall back to install_dir.
    if not base.exists() or not base.is_dir():
        base = Path(settings.install_dir).resolve()
    if not base.exists() or not base.is_dir():
        raise HTTPException(status_code=404, detail="Not a directory")

    entries: list[BrowseEntry] = []
    try:
        for child in sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                entries.append(BrowseEntry(name=child.name, path=str(child), is_dir=child.is_dir()))
            except OSError:
                continue
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")

    parent = str(base.parent) if base != base.parent else None
    return BrowseResult(path=str(base), parent=parent, entries=entries)


@router.post("/restart")
async def restart_service(user: AdminUser):
    asyncio.create_task(_delayed_restart())
    return {"status": "restarting", "message": "Service will restart in ~2 seconds"}


class PortUpdate(BaseModel):
    port: int


@router.get("/port")
async def get_port(user: AdminUser):
    """
    The port pktPCAP listens on. Lives in config.yaml (startup config, read
    before the DB connects) rather than the SQLite-backed settings table —
    see app/config.py.
    """
    return {"port": get_settings().port}


@router.post("/port")
async def set_port(user: AdminUser, body: PortUpdate):
    """
    Update the listen port in config.yaml. Takes effect on the next service
    restart — this only writes the file, it doesn't restart anything itself.
    """
    if not (1 <= body.port <= 65535):
        raise HTTPException(400, "Port must be between 1 and 65535")

    path = _config_file_path()
    text = path.read_text()
    new_line = f"port: {body.port}"
    if re.search(r"(?m)^port:\s*\d+", text):
        text = re.sub(r"(?m)^port:\s*\d+", new_line, text, count=1)
    else:
        text = text.rstrip("\n") + f"\n{new_line}\n"
    path.write_text(text)

    return {"port": body.port, "message": "Saved — restart the service to apply"}


# -- Local network interfaces -----------------------------------------------------
# Lists THIS pktPCAP host's own NICs — used only by the Wireshark-GUI SSH
# Remote Capture tab, where Wireshark SSHes into this same host to run the
# capture wrapper script here. It is NOT meant to introspect an arbitrary
# remote capture host for the generic tshark/curl flow (that flow has no
# agent on the remote box to ask, so its interface field stays free-text).

@router.get("/net-interfaces")
async def list_net_interfaces(user: CurrentUser):
    try:
        interfaces = [name for _, name in socket.if_nameindex()]
    except OSError:
        interfaces = []
    return {"interfaces": sorted(interfaces)}


def _ssl_dir() -> Path:
    return Path(get_settings().ssl_dir)


def _cert_file() -> Path:
    return _ssl_dir() / "server.crt"


def _key_file() -> Path:
    return _ssl_dir() / "server.key"


def _cert_info() -> dict:
    """Read cert metadata via openssl CLI. Returns {} on failure."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(_cert_file()), "-noout",
             "-enddate", "-subject", "-issuer"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip()}
        info: dict = {}
        for line in proc.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip().lower()
                if "notafter" in k or "enddate" in k:
                    info["expires"] = v.strip()
                elif k == "subject":
                    info["subject"] = v.strip()
                elif k == "issuer":
                    info["issuer"] = v.strip()
        try:
            from datetime import datetime, timezone
            exp = datetime.strptime(info["expires"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            info["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
            info["expires_iso"] = exp.isoformat()
        except Exception:
            pass
        return info
    except Exception as e:
        return {"error": str(e)}


@router.get("/ssl/status")
async def ssl_status(user: AdminUser) -> dict:
    """Return current SSL certificate status."""
    if not _cert_file().exists() or not _key_file().exists():
        return {"installed": False}
    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, **info}


@router.post("/ssl/upload")
async def upload_ssl_cert(
    user: AdminUser,
    cert: UploadFile = File(...),
    key: UploadFile = File(...),
) -> dict:
    """Upload and install a PEM certificate + private key."""
    cert_data = await cert.read()
    key_data  = await key.read()

    if b"-----BEGIN CERTIFICATE-----" not in cert_data:
        raise HTTPException(400, "Invalid certificate — must be PEM format (-----BEGIN CERTIFICATE-----)")
    if b"PRIVATE KEY-----" not in key_data:
        raise HTTPException(400, "Invalid private key — must be PEM format (-----BEGIN ... PRIVATE KEY-----)")

    def _save():
        _ssl_dir().mkdir(parents=True, exist_ok=True)
        _cert_file().write_bytes(cert_data)
        _cert_file().chmod(0o644)
        _key_file().write_bytes(key_data)
        _key_file().chmod(0o600)

    await asyncio.to_thread(_save)
    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, "status": "saved", **info}


@router.delete("/ssl/cert")
async def delete_ssl_cert(user: AdminUser) -> dict:
    """Remove the installed SSL certificate and key."""
    _cert_file().unlink(missing_ok=True)
    _key_file().unlink(missing_ok=True)
    return {"installed": False, "status": "removed"}


@router.post("/ssl/upload-pfx")
async def upload_ssl_pfx(
    user: AdminUser,
    pfx: UploadFile = File(...),
    passphrase: str = Form(...),
) -> dict:
    """
    Accept a PKCS#12 (.pfx/.p12) bundle + passphrase.
    Extracts the cert and private key as unencrypted PEM files
    (server.crt / server.key) so uvicorn can load them without interaction.
    """
    pfx_data = await pfx.read()

    def _extract() -> tuple[bool, str]:
        import tempfile
        _ssl_dir().mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mktemp(suffix=".pfx"))
        tmp.write_bytes(pfx_data)
        try:
            cert_proc = subprocess.run(
                ["openssl", "pkcs12",
                 "-in", str(tmp),
                 "-clcerts", "-nokeys",
                 "-passin", f"pass:{passphrase}",
                 "-out", str(_cert_file())],
                capture_output=True, text=True, timeout=15,
            )
            if cert_proc.returncode != 0:
                return False, f"Cert extraction failed: {cert_proc.stderr.strip()}"

            key_proc = subprocess.run(
                ["openssl", "pkcs12",
                 "-in", str(tmp),
                 "-nocerts", "-nodes",
                 "-passin", f"pass:{passphrase}",
                 "-out", str(_key_file())],
                capture_output=True, text=True, timeout=15,
            )
            if key_proc.returncode != 0:
                return False, f"Key extraction failed: {key_proc.stderr.strip()}"

            _cert_file().chmod(0o644)
            _key_file().chmod(0o600)
            return True, "ok"
        finally:
            tmp.unlink(missing_ok=True)

    ok, msg = await asyncio.to_thread(_extract)
    if not ok:
        raise HTTPException(400, msg)

    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, "status": "saved", **info}


@router.get("/backups")
async def list_backups(user: AdminUser):
    settings = get_settings()
    return await asyncio.to_thread(list_backups_sync, settings.db_path)


@router.post("/backups/run")
async def run_backup_now(user: AdminUser):
    settings = get_settings()
    result = await asyncio.to_thread(run_backup_sync, settings.db_path)
    if result.get("status") != "ok":
        raise HTTPException(status_code=500, detail="Backup failed")
    return result


class ExportRequest(BaseModel):
    password: str


async def _verify_export_password(user: dict, password: str) -> None:
    """Step-up re-auth for the full backup bundle.

    The bundle deliberately contains both the database and config.yaml,
    because a restore is useless without them — but that pairing means one
    downloaded file holds every encrypted secret AND the key that decrypts
    them, and it lands wherever the browser puts downloads. Being logged in as
    an admin is not a high enough bar to hand that over, so the caller
    re-enters their current password: the same bar as revealing any other
    stored secret.

    Suite-proxied callers (X-Suite-Token, synthetic user id 0) have no local
    password and are always rejected — they must log in as a real local admin.
    """
    from app.auth.local import verify_password

    _settings = get_settings()
    async with aiosqlite.connect(_settings.db_path) as _conn:
        _conn.row_factory = aiosqlite.Row
        async with _conn.execute(
            "SELECT hashed_password FROM users WHERE id = ?", (user["id"],)
        ) as _cur:
            _row = await _cur.fetchone()
    if not _row or not verify_password(password, _row["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")


@router.post("/export")
async def export_bundle(body: ExportRequest, user: AdminUser):
    await _verify_export_password(user, body.password)

    """Download a full backup bundle as a .tar.gz archive: pktpcap.db + config.yaml."""
    settings = get_settings()
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"pktpcap-export-{date_str}.tar.gz"

    def _build_archive(out_path: Path) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            db = Path(settings.db_path)
            if db.exists():
                shutil.copy2(str(db), str(tmp_path / "pktpcap.db"))

            for candidate in [Path("config.yaml"), Path(settings.install_dir) / "config.yaml"]:
                if candidate.exists():
                    shutil.copy2(str(candidate), str(tmp_path / "config.yaml"))
                    break

            with tarfile.open(str(out_path), "w:gz") as tar:
                for f in tmp_path.iterdir():
                    tar.add(str(f), arcname=f.name)

    tmp_out = Path(tempfile.mktemp(suffix=".tar.gz"))
    try:
        await asyncio.to_thread(_build_archive, tmp_out)

        def _iterfile():
            try:
                with open(tmp_out, "rb") as f:
                    while chunk := f.read(65536):
                        yield chunk
            finally:
                tmp_out.unlink(missing_ok=True)

        return StreamingResponse(
            _iterfile(),
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception:
        tmp_out.unlink(missing_ok=True)
        raise


def _restore_from_dir(src_dir: Path, settings, files: Optional[set[str]]) -> dict:
    """
    Restore whatever of {pktpcap.db, config.yaml, captures} is present in
    src_dir and selected by `files` (None means restore everything present).
    `captures` is a directory (only present in on-server snapshots taken with
    "Include captures" enabled — bundle uploads never include it).
    """
    result: dict = {}

    def wanted(name: str) -> bool:
        return files is None or name in files

    db_src = src_dir / "pktpcap.db"
    if wanted("pktpcap.db"):
        if db_src.exists():
            shutil.copy2(str(db_src), settings.db_path)
            result["pktpcap.db"] = "restored"
        else:
            result["pktpcap.db"] = "not found in backup"

    cfg_src = src_dir / "config.yaml"
    if wanted("config.yaml"):
        if cfg_src.exists():
            shutil.copy2(str(cfg_src), str(Path(settings.install_dir) / "config.yaml"))
            result["config.yaml"] = "restored (restart required)"
        else:
            result["config.yaml"] = "not found in backup"

    captures_src = src_dir / "captures"
    if wanted("captures"):
        if captures_src.is_dir():
            shutil.copytree(str(captures_src), settings.storage_path, dirs_exist_ok=True)
            result["captures"] = "restored"
        else:
            result["captures"] = "not present in backup"

    return result


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract `tar` into `dest`, rejecting any member whose resolved path
    would land outside `dest` (tar-slip / path-traversal via `../` segments,
    absolute paths, or symlink tricks in member names). The export bundle is
    admin-generated by pktPCAP itself, but import accepts an arbitrary
    uploaded .tar.gz, so treat it as untrusted input."""
    dest = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if member_path != dest and dest not in member_path.parents:
            raise ValueError(f"Unsafe path in archive: {member.name}")
        # Also reject symlink/hardlink members pointing outside dest, even if
        # their own name looks safe.
        if member.issym() or member.islnk():
            link_target = (dest / member.linkname).resolve() if not Path(member.linkname).is_absolute() \
                else Path(member.linkname).resolve()
            if link_target != dest and dest not in link_target.parents:
                raise ValueError(f"Unsafe link target in archive: {member.name} -> {member.linkname}")
    tar.extractall(dest)


def _parse_files_param(files: Optional[str]) -> Optional[set[str]]:
    if not files:
        return None
    return {f.strip() for f in files.split(",") if f.strip()}


@router.post("/import")
async def import_bundle(user: AdminUser, file: UploadFile = File(...), files: Optional[str] = Form(None)):
    """
    Restore from a pktpcap export bundle (.tar.gz).
    `files` is an optional comma-separated subset of {pktpcap.db, config.yaml} —
    omit to restore everything present in the bundle.
    Requires a service restart after restore for config changes to take effect.
    """
    settings = get_settings()
    data = await file.read()
    wanted = _parse_files_param(files)

    def _do_restore(raw: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_path = tmp_path / "upload.tar.gz"
            archive_path.write_bytes(raw)

            try:
                with tarfile.open(str(archive_path), "r:gz") as tar:
                    _safe_extract(tar, tmp_path)
            except Exception as e:
                return {"error": f"Failed to extract archive: {e}"}

            return _restore_from_dir(tmp_path, settings, wanted)

    result = await asyncio.to_thread(_do_restore, data)
    return result


@router.post("/backups/restore/{snapshot_name}")
async def restore_from_snapshot(user: AdminUser, snapshot_name: str, files: Optional[str] = None) -> dict:
    """
    Restore directly from an on-server backup snapshot — no download/upload round trip.
    `files` is an optional comma-separated subset of {pktpcap.db, config.yaml,
    captures} — omit to restore everything present in the snapshot.
    """
    if not re.fullmatch(r"backup_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}", snapshot_name):
        raise HTTPException(status_code=400, detail="Invalid snapshot name")

    settings = get_settings()
    s = await asyncio.to_thread(_read_backup_settings_sync, settings.db_path)
    backup_root = Path(s["backup_path"]).resolve()
    snap_dir = (backup_root / snapshot_name).resolve()
    if snap_dir.parent != backup_root or not snap_dir.is_dir():
        raise HTTPException(status_code=404, detail="Snapshot not found")

    wanted = _parse_files_param(files)
    result = await asyncio.to_thread(_restore_from_dir, snap_dir, settings, wanted)
    return result
