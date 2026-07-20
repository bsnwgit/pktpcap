"""
Scheduled on-server backup job.

Runs at a configurable interval (default every 24 hours) in a background thread.
Each run creates a timestamped snapshot directory under backup_path:
  <backup_path>/backup_2026-06-24_22-00/
    pktpcap.db
    config.json
    captures/         (if backup_include_captures is True)

Rotates snapshots — keeps the newest `backup_rotation` directories and
deletes older ones.
"""
from __future__ import annotations

import logging
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger("pktpcap.backup")

BASE = Path(__file__).parent


def _default_backup_root(cfg: dict) -> Path:
    path = cfg.get("backup_path") or ""
    return Path(path) if path else (BASE / "backups")


def _paths_overlap(a: Path, b: Path) -> bool:
    """True if `a` and `b` are the same directory, or one contains the other."""
    a, b = a.resolve(), b.resolve()
    return a == b or a in b.parents or b in a.parents


def run_backup(cfg: dict, db_path: str) -> dict:
    """Perform one backup run. Returns a dict describing what was done."""
    result: dict = {"status": "ok", "path": "", "files": []}

    backup_root = _default_backup_root(cfg)
    backup_root.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    snap_dir = backup_root / f"backup_{ts}"
    suffix = 1
    while snap_dir.exists():
        # Same-second collision (e.g. "Run Backup Now" clicked twice quickly) —
        # never silently overwrite a previous snapshot.
        suffix += 1
        snap_dir = backup_root / f"backup_{ts}-{suffix}"
    snap_dir.mkdir(parents=True)
    result["path"] = str(snap_dir)

    db_src = Path(db_path)
    if not db_src.is_absolute():
        db_src = BASE / db_src
    if db_src.exists():
        shutil.copy2(str(db_src), str(snap_dir / "pktpcap.db"))
        result["files"].append("pktpcap.db")

    config_src = BASE / "config.json"
    if config_src.exists():
        shutil.copy2(str(config_src), str(snap_dir / "config.json"))
        result["files"].append("config.json")

    if cfg.get("backup_include_captures"):
        captures_src = Path(cfg.get("storage_path") or "")
        if captures_src.exists() and captures_src.is_dir():
            if _paths_overlap(captures_src, backup_root):
                log.warning(f"Skipping capture backup: storage_path overlaps backup_path ({captures_src} / {backup_root})")
            else:
                try:
                    shutil.copytree(str(captures_src), str(snap_dir / "captures"))
                    result["files"].append("captures/")
                except Exception as e:
                    log.warning(f"Capture backup failed: {e}")

    keep = int(cfg.get("backup_rotation") or 7)
    snapshots = sorted(
        [d for d in backup_root.iterdir() if d.is_dir() and d.name.startswith("backup_")],
        key=lambda d: d.stat().st_mtime,
    )
    removed = []
    while len(snapshots) > keep:
        old = snapshots.pop(0)
        shutil.rmtree(str(old), ignore_errors=True)
        removed.append(old.name)
    if removed:
        log.info(f"Backup rotation: removed {removed}")

    result["kept"] = len(snapshots)
    log.info(f"Backup complete: {snap_dir} — files: {result['files']}")
    return result


def list_backups(cfg: dict) -> list:
    """List existing backup snapshots, newest first."""
    backup_root = _default_backup_root(cfg)
    if not backup_root.exists():
        return []
    snapshots = sorted(
        [d for d in backup_root.iterdir() if d.is_dir() and d.name.startswith("backup_")],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    out = []
    for snap in snapshots:
        try:
            size = sum(f.stat().st_size for f in snap.rglob("*") if f.is_file())
            files = [f.name for f in snap.iterdir()]
            out.append({
                "name": snap.name,
                "size_bytes": size,
                "files": files,
                "created_at": datetime.fromtimestamp(snap.stat().st_mtime).isoformat(),
            })
        except Exception:
            pass
    return out


def start_scheduler(load_config, db_path: str):
    """Start the background thread that runs scheduled backups. Non-blocking."""
    def _loop():
        while True:
            try:
                cfg = load_config()
                if cfg.get("auto_backup"):
                    run_backup(cfg, db_path)
                interval_hours = max(1, int(cfg.get("backup_interval_hours") or 24))
            except Exception as e:
                log.error(f"Backup scheduler error: {e}")
                interval_hours = 24
            time.sleep(interval_hours * 3600)

    threading.Thread(target=_loop, daemon=True).start()
    log.info("Backup scheduler started")
