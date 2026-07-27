"""
/api/captures/* — persisted .pcapng files. Metadata comes from the
`captures` DB table (migrations/002_captures.sql); bytes come from disk at
storage_path. See app/capture/storage.py and app/capture/reconcile.py.

GET    /api/captures                — list, DB-backed (status/source/size/created_at)
GET    /api/captures/{fname}/download
DELETE /api/captures/{fname}
POST   /api/captures/upload         — drag-and-drop upload from the Upload page
"""
from __future__ import annotations

from pathlib import Path

import aiosqlite
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.capture.storage import CAPTURE_FILE_RE, captures_dir
from app.database import get_db
from app.dependencies import CurrentUser

router = APIRouter()


def _out(r) -> dict:
    return {
        "id": r["id"],
        "filename": r["filename"],
        "session_name": r["session_name"],
        "source": r["source"],
        "size_bytes": r["size_bytes"],
        "status": r["status"],
        "created_by": r["created_by"],
        "created_at": r["created_at"],
    }


@router.get("")
async def list_captures(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    d = await captures_dir(db)
    async with db.execute("SELECT * FROM captures ORDER BY created_at DESC") as cur:
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
    fpath = d / fname
    if not fpath.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(str(fpath), media_type="application/octet-stream", filename=fname)


@router.delete("/{fname}")
async def delete_capture(fname: str, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    """Delete means delete — removes the file (if present) and the DB row.
    'missing' status is only ever set by reconciliation noticing a file
    vanished outside the API (crash, manual rm, storage_path pointed
    somewhere wrong) — an explicit user delete here is unambiguous and
    shouldn't leave a row behind that needs a second click to clear."""
    if not CAPTURE_FILE_RE.match(fname):
        raise HTTPException(status_code=404, detail="Not found")

    async with db.execute("SELECT id FROM captures WHERE filename = ?", (fname,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")

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
        """INSERT INTO captures (filename, session_name, source, status, size_bytes, created_by)
           VALUES (?, NULL, 'upload', 'saved', ?, ?)
           ON CONFLICT(filename) DO UPDATE SET status = 'saved', size_bytes = excluded.size_bytes""",
        (fname, len(data), user["id"]),
    )
    await db.commit()

    return {"ok": True, "filename": fname, "size_bytes": len(data)}
