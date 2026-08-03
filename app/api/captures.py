"""
/api/captures/* — persisted .pcapng files. Metadata comes from the
`captures` DB table (migrations/002_captures.sql, 003_capture_sharing.sql);
bytes come from disk at storage_path. See app/capture/storage.py and
app/capture/reconcile.py.

GET    /api/captures                — list, visibility-filtered (see below)
GET    /api/captures/{fname}/download
DELETE /api/captures/{fname}
POST   /api/captures/upload         — drag-and-drop upload from the Upload page
PUT    /api/captures/{fname}/shared — owner or admin only

Visibility model: a capture is private to its owner (created_by) unless
`shared` is set, in which case every signed-in user can see it (and it's
labeled with the owner's username so other users know where it came from).
Admins always see everything, same as they already do elsewhere in the
suite. Captures with no owner (created_by IS NULL — Wireshark SSH
remote-capture pushes have no pktPCAP user context to attribute to at all)
predate this feature and stay visible to everyone regardless of `shared`.
"""
from __future__ import annotations

from pathlib import Path

import aiosqlite
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.capture.storage import CAPTURE_FILE_RE, captures_dir
from app.database import get_db
from app.dependencies import CurrentUser

router = APIRouter()


class SharedUpdate(BaseModel):
    shared: bool


def _out(r) -> dict:
    return {
        "id": r["id"],
        "filename": r["filename"],
        "session_name": r["session_name"],
        "source": r["source"],
        "size_bytes": r["size_bytes"],
        "status": r["status"],
        "created_by": r["created_by"],
        "owner_username": r["owner_username"],
        "shared": bool(r["shared"]),
        "created_at": r["created_at"],
    }


_SELECT = """
    SELECT c.*, u.username AS owner_username
    FROM captures c
    LEFT JOIN users u ON u.id = c.created_by
"""


async def _get_capture_row(db: aiosqlite.Connection, fname: str):
    async with db.execute(_SELECT + " WHERE c.filename = ?", (fname,)) as cur:
        return await cur.fetchone()


def _can_manage(row, user: dict) -> bool:
    """Owner or admin — used for delete + the shared toggle. Unowned
    captures (created_by IS NULL) stay manageable by anyone, matching the
    no-ownership-check behavior that existed for all captures before this
    feature."""
    if user["role"] == "admin":
        return True
    if row["created_by"] is None:
        return True
    return row["created_by"] == user["id"]


def _can_view(row, user: dict) -> bool:
    if user["role"] == "admin":
        return True
    if row["created_by"] is None or bool(row["shared"]):
        return True
    return row["created_by"] == user["id"]


@router.get("")
async def list_captures(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    d = await captures_dir(db)
    if user["role"] == "admin":
        async with db.execute(_SELECT + " ORDER BY c.created_at DESC") as cur:
            rows = await cur.fetchall()
    else:
        async with db.execute(
            _SELECT + " WHERE c.created_by = ? OR c.created_by IS NULL OR c.shared = 1 ORDER BY c.created_at DESC",
            (user["id"],),
        ) as cur:
            rows = await cur.fetchall()
    return {
        "storage_path_configured": d is not None,
        "captures": [_out(r) for r in rows],
    }


@router.get("/{fname}/download")
async def download_capture(fname: str, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    d = await captures_dir(db)
    if not d or not CAPTURE_FILE_RE.match(fname):
        raise HTTPException(status_code=404, detail="Not found")
    row = await _get_capture_row(db, fname)
    if not row or not _can_view(row, user):
        raise HTTPException(status_code=404, detail="Not found")
    fpath = d / fname
    if not fpath.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(str(fpath), media_type="application/octet-stream", filename=fname)


@router.put("/{fname}/shared")
async def set_capture_shared(fname: str, body: SharedUpdate, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    if not CAPTURE_FILE_RE.match(fname):
        raise HTTPException(status_code=404, detail="Not found")
    row = await _get_capture_row(db, fname)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    if not _can_manage(row, user):
        raise HTTPException(status_code=403, detail="Only the owner or an admin can change sharing on this capture")

    await db.execute("UPDATE captures SET shared = ? WHERE filename = ?", (int(body.shared), fname))
    await db.commit()
    row = await _get_capture_row(db, fname)
    return _out(row)


@router.delete("/{fname}")
async def delete_capture(fname: str, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    """Delete means delete — removes the file (if present) and the DB row.
    'missing' status is only ever set by reconciliation noticing a file
    vanished outside the API (crash, manual rm, storage_path pointed
    somewhere wrong) — an explicit user delete here is unambiguous and
    shouldn't leave a row behind that needs a second click to clear."""
    if not CAPTURE_FILE_RE.match(fname):
        raise HTTPException(status_code=404, detail="Not found")

    row = await _get_capture_row(db, fname)
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    if not _can_manage(row, user):
        raise HTTPException(status_code=403, detail="Only the owner or an admin can delete this capture")

    d = await captures_dir(db)
    if d:
        fpath = d / fname
        try:
            fpath.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            raise HTTPException(status_code=500, detail=str(e))

    await db.execute("DELETE FROM captures WHERE filename = ?", (fname,))
    await db.commit()
    return {"ok": True}


@router.post("/upload")
async def upload_capture(
    user: CurrentUser,
    db: aiosqlite.Connection = Depends(get_db),
    file: UploadFile = File(...),
    shared: bool = Form(False),
):
    d = await captures_dir(db)
    if not d:
        raise HTTPException(
            status_code=400,
            detail="No capture storage path configured — set one in Settings → Captures",
        )
    fname = Path(file.filename or "upload.pcapng").name
    if not fname.endswith((".pcap", ".pcapng", ".cap")):
        fname = f"{fname}.pcapng"
    if not CAPTURE_FILE_RE.match(fname):
        # Normalize into a valid, unique-ish name rather than rejecting the upload outright.
        import re as _re
        import time as _time
        stem = _re.sub(r"[^a-zA-Z0-9_-]", "_", Path(fname).stem)[:60] or "upload"
        fname = f"{stem}_{int(_time.time())}.pcapng"

    data = await file.read()
    d.mkdir(parents=True, exist_ok=True)
    (d / fname).write_bytes(data)

    await db.execute(
        """INSERT INTO captures (filename, session_name, source, status, size_bytes, created_by, shared)
           VALUES (?, NULL, 'upload', 'saved', ?, ?, ?)
           ON CONFLICT(filename) DO UPDATE SET status = 'saved', size_bytes = excluded.size_bytes""",
        (fname, len(data), user["id"], int(shared)),
    )
    await db.commit()

    return {"ok": True, "filename": fname, "size_bytes": len(data)}
