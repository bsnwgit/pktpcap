"""
/api/system/* — version info, SSL, backups, and admin diagnostics.
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import subprocess
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from app.config import get_settings
from app.dependencies import AdminUser, CurrentUser
from app.backup import run_backup_sync, list_backups_sync

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
async def system_info(user: CurrentUser):
    settings = get_settings()
    return {
        "version": "0.1.0",
        "install_dir": settings.install_dir,
        "port": settings.port,
    }


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
