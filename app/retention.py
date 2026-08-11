"""
Capture retention scheduler.

Settings → Captures has always offered a **Retention** window and an
**Auto-purge** toggle whose help text reads "automatically delete captures past
the retention window". Nothing in the backend ever read either key. The toggle
was inert: persisted `.pcapng` files accumulated in storage_path forever, and
their rows in `captures` with them, no matter what an operator set.

Packet captures are the largest artifacts anything in this suite writes — a
single busy feed can produce gigabytes — so this is the app where unbounded
growth fills a disk in days rather than months.

This honours the existing contract rather than inventing new keys: `auto_purge`
gates it and `retention_days` sets the window, exactly as the UI already says.
Purging stays off unless the operator turned that toggle on, because a capture
is usually evidence someone deliberately kept and cannot be re-collected.

The file is removed before its row. If the process dies between the two, the
next run sees a row whose file is missing and can still clear it; the reverse
order would leave an orphaned file that nothing knows about.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import aiosqlite

from app.database import DB_PATH

log = logging.getLogger("pktpcap.retention")

# Retention is expressed in days, so once a day is enough.
_INTERVAL_SECONDS = 86_400

# Let startup settle before the first sweep.
_FIRST_RUN_DELAY_SECONDS = 300

# Matches the Settings → Captures default. Irrelevant unless auto_purge is on.
_DEFAULT_RETENTION_DAYS = 90


class CaptureRetention:
    def __init__(self, interval_seconds: int = _INTERVAL_SECONDS):
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run_loop())
        log.info(f"Capture retention started (interval={self._interval}s)")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _setting(self, db: aiosqlite.Connection, key: str):
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return row[0]

    async def run_once(self) -> dict:
        async with aiosqlite.connect(DB_PATH) as db:
            if not bool(await self._setting(db, "auto_purge")):
                log.info("Capture retention: auto_purge is off — skipping")
                return {"skipped": True, "reason": "auto_purge off"}

            try:
                days = int(await self._setting(db, "retention_days") or _DEFAULT_RETENTION_DAYS)
            except (TypeError, ValueError):
                days = _DEFAULT_RETENTION_DAYS

            if days <= 0:
                log.info("Capture retention disabled (retention_days <= 0) — skipping")
                return {"skipped": True, "retention_days": days}

            raw_dir = await self._setting(db, "storage_path")
            if not raw_dir:
                log.info("Capture retention: no storage_path set — nothing persisted, skipping")
                return {"skipped": True, "reason": "no storage_path"}
            base = Path(str(raw_dir))

            async with db.execute(
                "SELECT id, filename FROM captures WHERE created_at < datetime('now', ?)",
                (f"-{days} days",),
            ) as cur:
                rows = await cur.fetchall()

            removed_files = 0
            missing = 0
            for cap_id, filename in rows:
                target = base / filename
                try:
                    if target.is_file():
                        target.unlink()
                        removed_files += 1
                    else:
                        missing += 1
                except OSError as e:
                    # Leave the row in place so the next run retries this file
                    # rather than losing track of bytes still on disk.
                    log.warning(f"Capture retention: could not remove {target} ({e})")
                    continue
                await db.execute("DELETE FROM captures WHERE id = ?", (cap_id,))
            await db.commit()

        log.info(
            f"Capture retention run complete: {removed_files} file(s) removed, "
            f"{missing} row(s) had no file, {len(rows)} eligible (retention={days}d)"
        )
        return {"removed": removed_files, "missing": missing, "eligible": len(rows)}

    async def _run_loop(self) -> None:
        await asyncio.sleep(_FIRST_RUN_DELAY_SECONDS)
        while True:
            try:
                await self.run_once()
            except Exception as e:
                log.error(f"Capture retention error: {e}")
            await asyncio.sleep(self._interval)
