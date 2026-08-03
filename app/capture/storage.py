"""
On-disk capture persistence + the `captures` DB metadata index (see
migrations/002_captures.sql). storage_path is read from the SQLite settings
table (Settings → Captures), matching the old Flask app's behavior exactly:
there is no config.yaml fallback for this — captures stay memory-only until
an admin explicitly sets storage_path, same "off by default, explicit
opt-in" behavior as before. (config.py's `storage_path` field is only a
suggested default the Settings UI can pre-fill; the backend never falls
back to it for the actual persistence gate.)
"""
from __future__ import annotations

import datetime
import json
import logging
import re
from pathlib import Path
from typing import Optional

import aiosqlite

from app.capture.feed_sessions import FeedSession
from app.database import DB_PATH

log = logging.getLogger("pktpcap.capture.storage")

CAPTURE_FILE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,79}\.pcapng$")


async def _get_setting(db: aiosqlite.Connection, key: str):
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return row[0]


async def captures_dir(db: Optional[aiosqlite.Connection] = None) -> Optional[Path]:
    """The configured on-disk capture directory (Settings → Captures →
    Storage path), or None if not configured."""
    if db is not None:
        storage_path = await _get_setting(db, "storage_path")
    else:
        async with aiosqlite.connect(DB_PATH) as _db:
            storage_path = await _get_setting(_db, "storage_path")
    storage_path = (storage_path or "").strip()
    return Path(storage_path) if storage_path else None


async def _insert_capture_row(
    db: aiosqlite.Connection,
    filename: str,
    session_name: Optional[str],
    source: str,
    status: str,
    size_bytes: Optional[int] = None,
    created_by: Optional[int] = None,
) -> None:
    await db.execute(
        """INSERT INTO captures (filename, session_name, source, status, size_bytes, created_by)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(filename) DO UPDATE SET
             status = excluded.status, size_bytes = excluded.size_bytes""",
        (filename, session_name, source, status, size_bytes, created_by),
    )
    await db.commit()


async def save_feed_to_disk(feed_session: FeedSession) -> Optional[str]:
    """Persist a finished feed session's buffered bytes to storage_path so it
    survives past the in-memory session (200MB cap, lost on restart/eviction).
    No-ops quietly if no storage_path is configured — same as before.

    Records a `captures` row: 'saving' before the write, 'saved'/'failed'
    after, so a crash mid-write is visible instead of silently absent (this
    is new — the old app tracked nothing in the DB, only the filesystem).
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        d = await captures_dir(db)
        if not d:
            return None
        data = await feed_session.get_bytes()
        if not data:
            return None

        source = "wireshark" if feed_session.name.startswith("ws-") else "tshark"
        ts = datetime.datetime.fromtimestamp(feed_session.last_seen).strftime("%Y%m%d-%H%M%S")
        fname = f"{feed_session.name}_{ts}.pcapng"

        owner = feed_session.owner_user_id
        await _insert_capture_row(db, fname, feed_session.name, source, "saving", created_by=owner)
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / fname).write_bytes(data)
            await _insert_capture_row(db, fname, feed_session.name, source, "saved", size_bytes=len(data), created_by=owner)
            log.info("Saved capture %s (%d bytes) to %s", fname, len(data), d)
            return fname
        except OSError:
            log.exception("Failed to save feed %s to storage_path", feed_session.name)
            await _insert_capture_row(db, fname, feed_session.name, source, "failed", created_by=owner)
            return None
