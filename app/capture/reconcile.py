"""
Reconciles the `captures` DB table against what's actually on disk at
storage_path. Runs once at startup (covers manually-copied files, and the
one-time migration of captures the old Flask app persisted before this DB
table existed) and periodically afterward (covers files dropped in by hand
later, or files deleted outside the API).

Files on disk with no DB row     -> inserted as status='saved', source='unknown'
DB rows with no file on disk     -> marked status='missing' (not deleted — keeps
                                     the record so the UI can show what went away)
DB rows marked 'missing' whose
file is back on disk             -> recovered to status='saved' (covers a
                                     storage_path fixed after being briefly wrong,
                                     or a file restored from backup)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiosqlite

from app.capture.storage import CAPTURE_FILE_RE, captures_dir
from app.database import DB_PATH

log = logging.getLogger("pktpcap.capture.reconcile")

_INTERVAL_SECONDS = 300  # 5 minutes


async def reconcile_once() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        d = await captures_dir(db)

        async with db.execute("SELECT filename, status FROM captures") as cur:
            db_rows = {r["filename"]: r["status"] for r in await cur.fetchall()}

        on_disk: set[str] = set()
        if d and d.is_dir():
            for f in d.iterdir():
                if f.is_file() and CAPTURE_FILE_RE.match(f.name):
                    on_disk.add(f.name)

        inserted = 0
        for fname in on_disk - db_rows.keys():
            try:
                size = (d / fname).stat().st_size
            except OSError:
                size = None
            await db.execute(
                """INSERT INTO captures (filename, session_name, source, status, size_bytes)
                   VALUES (?, NULL, 'unknown', 'saved', ?)
                   ON CONFLICT(filename) DO NOTHING""",
                (fname, size),
            )
            inserted += 1

        missing = 0
        recovered = 0
        for fname, status in db_rows.items():
            if fname not in on_disk and status != "missing":
                await db.execute(
                    "UPDATE captures SET status = 'missing' WHERE filename = ?", (fname,)
                )
                missing += 1
            elif fname in on_disk and status == "missing":
                try:
                    size = (d / fname).stat().st_size if d else None
                except OSError:
                    size = None
                await db.execute(
                    "UPDATE captures SET status = 'saved', size_bytes = ? WHERE filename = ?",
                    (size, fname),
                )
                recovered += 1

        await db.commit()

    result = {"inserted": inserted, "marked_missing": missing, "recovered": recovered}
    if inserted or missing or recovered:
        log.info("Capture reconciliation: %s", result)
    return result


class ReconcileTask:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        await reconcile_once()
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_loop(self) -> None:
        while True:
            await asyncio.sleep(_INTERVAL_SECONDS)
            try:
                await reconcile_once()
            except Exception as e:
                log.error(f"Reconciliation error: {e}")
