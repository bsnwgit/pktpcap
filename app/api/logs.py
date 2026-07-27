"""
/api/logs/* — pktPCAP's own application log (app_logs table).

Endpoints
~~~~~~~~~
GET    /api/logs        — paginated log records (level/logger/search/since/until filters)
GET    /api/logs/stats  — counts by level, distinct loggers, latest timestamp, capture level
DELETE /api/logs        — clear all log records (admin only)
POST   /api/logs/level  — set runtime capture level (admin only)
"""
from __future__ import annotations

import logging
from typing import Annotated, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import get_db
from app.dependencies import AdminUser, CurrentUser

router = APIRouter()

_LEVEL_MAP = {
    "DEBUG":    logging.DEBUG,
    "INFO":     logging.INFO,
    "WARNING":  logging.WARNING,
    "ERROR":    logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


# ── GET /api/logs ─────────────────────────────────────────────────────────────

@router.get("")
async def get_logs(
    _user: CurrentUser,
    db: Annotated[aiosqlite.Connection, Depends(get_db)],
    level: Optional[str] = Query(None, description="Minimum level name (e.g. WARNING)"),
    logger: Optional[str] = Query(None, description="Logger name prefix filter"),
    search: Optional[str] = Query(None, description="Full-text search in message"),
    since: Optional[str] = Query(None, description="ISO timestamp lower bound"),
    until: Optional[str] = Query(None, description="ISO timestamp upper bound"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    conditions: list[str] = []
    params: list = []

    if level:
        level_no = _LEVEL_MAP.get(level.upper())
        if level_no is not None:
            conditions.append("level_no >= ?")
            params.append(level_no)

    if logger:
        conditions.append("logger LIKE ?")
        params.append(f"{logger}%")

    if search:
        conditions.append("message LIKE ?")
        params.append(f"%{search}%")

    if since:
        conditions.append("created_at >= ?")
        params.append(since)

    if until:
        conditions.append("created_at <= ?")
        params.append(until)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    async with db.execute(f"SELECT COUNT(*) FROM app_logs {where}", params) as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        f"""
        SELECT id, created_at, level, level_no, logger, message, exc_info
        FROM app_logs
        {where}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ) as cur:
        rows = await cur.fetchall()

    records = [
        {
            "id":       r["id"],
            "ts":       r["created_at"],
            "level":    r["level"],
            "level_no": r["level_no"],
            "logger":   r["logger"],
            "message":  r["message"],
            "exc_info": r["exc_info"],
        }
        for r in rows
    ]

    return {"total": total, "limit": limit, "offset": offset, "records": records}


# ── GET /api/logs/stats ───────────────────────────────────────────────────────

@router.get("/stats")
async def get_log_stats(
    _user: CurrentUser,
    db: Annotated[aiosqlite.Connection, Depends(get_db)],
):
    async with db.execute("SELECT COUNT(*) FROM app_logs") as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        "SELECT level, COUNT(*) as cnt FROM app_logs GROUP BY level"
    ) as cur:
        by_level = {r["level"]: r["cnt"] for r in await cur.fetchall()}

    async with db.execute(
        "SELECT DISTINCT logger FROM app_logs ORDER BY logger"
    ) as cur:
        loggers = [r["logger"] for r in await cur.fetchall()]

    async with db.execute("SELECT MAX(created_at) FROM app_logs") as cur:
        latest_ts = (await cur.fetchone())[0]

    root_handler = _get_sqlite_handler()
    current_level = logging.getLevelName(root_handler.level) if root_handler else "WARNING"

    return {
        "total":         total,
        "by_level":      by_level,
        "loggers":       loggers,
        "latest_ts":     latest_ts,
        "capture_level": current_level,
    }


# ── DELETE /api/logs ──────────────────────────────────────────────────────────

@router.delete("")
async def clear_logs(
    _user: AdminUser,
    db: Annotated[aiosqlite.Connection, Depends(get_db)],
):
    await db.execute("DELETE FROM app_logs")
    await db.commit()
    return {"status": "ok", "message": "Log records cleared"}


# ── POST /api/logs/level ──────────────────────────────────────────────────────

@router.post("/level")
async def set_capture_level(
    _user: AdminUser,
    level: str = Query(..., description="DEBUG | INFO | WARNING | ERROR | CRITICAL"),
):
    level_upper = level.upper()
    if level_upper not in _LEVEL_MAP:
        raise HTTPException(status_code=400, detail=f"Invalid level: {level}")

    level_no = _LEVEL_MAP[level_upper]
    handler = _get_sqlite_handler()
    if handler:
        handler.set_level(level_no)
        if logging.root.level > level_no:
            logging.root.setLevel(level_no)

    return {"status": "ok", "capture_level": level_upper}


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_sqlite_handler():
    """Return the first SQLiteLogHandler found on the pktpcap logger, if any."""
    try:
        from app.logging_handler import SQLiteLogHandler
        for h in logging.getLogger("pktpcap").handlers:
            if isinstance(h, SQLiteLogHandler):
                return h
    except ImportError:
        pass
    return None
