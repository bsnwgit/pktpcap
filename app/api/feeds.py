"""
/api/feed/{name}  (POST)  — streaming tshark/Wireshark pcapng ingest
/api/feeds        (GET)   — list active in-memory feed sessions, filtered to
    the caller's own sessions (admins see all)
/api/feeds/{name}/download (GET) — owner or admin only
/api/feeds/{name} (DELETE) — owner or admin only
/api/capture/wrapper-config (GET) — unauthenticated but loopback-only
    (enforced in code, not just "in practice"); see the docstring below for
    why this exists.

Mounted at prefix "/api" in app/main.py (not "/api/feeds") because the
ingest route is intentionally singular (/api/feed/<name>, matching the old
Flask app and the service/pktpcap wrapper script's hardcoded URL) while
everything else here is plural (/api/feeds/*).
"""
from __future__ import annotations

import json
import re
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.capture.auth import require_feed_token
from app.capture.storage import save_feed_to_disk
from app.database import DB_PATH
from app.dependencies import CurrentUser

router = APIRouter()

_FEED_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")


async def _get_setting(key: str, default=None):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return row[0]


# -- Wrapper-script config bootstrap ----------------------------------------------
# scripts/pktpcap (the Wireshark SSH-remote-capture wrapper) runs on this same
# host and needs to know whether it's allowed to push, and what feed_token to
# use, before every capture. The old Flask app let it call the generic
# GET /api/settings unauthenticated (via its own now-removed global
# auth-disabled bypass); the rebuilt /api/settings requires a real login, so
# a small dedicated endpoint covers just the two fields the wrapper needs.
# This is a deliberate, scoped exception — not a blanket settings bypass —
# but it hands out feed_token in the clear, so it must not be reachable off
# the box. scripts/pktpcap always calls it via `http://localhost:__PORT__`
# (see that script), so it's enforced here as loopback-only rather than
# trusted to stay "unauthenticated in practice": any request whose peer
# address isn't 127.0.0.1/::1 gets a 404, same as if the route didn't exist.

@router.get("/capture/wrapper-config")
async def wrapper_config(request: Request):
    client_host = request.client.host if request.client else None
    if client_host not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return {
        "wireshark_capture_enabled": bool(await _get_setting("wireshark_capture_enabled", False)),
        "tshark_capture_enabled": bool(await _get_setting("tshark_capture_enabled", True)),
        "feed_token": await _get_setting("feed_token", "") or "",
        "default_capture_duration_seconds": await _get_setting("default_capture_duration_seconds", 0) or 0,
    }


@router.post("/feed/{name}", dependencies=[Depends(require_feed_token)])
async def receive_feed(name: str, request: Request, owner: Optional[int] = None):
    """Streaming endpoint — tshark/Wireshark pushes raw pcapng bytes here.

    `owner` (optional query param) is the pktPCAP user id that generated
    this push command — embedded by the Live Feeds page's tshark/curl
    command builder for the currently signed-in user, purely so the
    resulting capture can be attributed for the sharing feature (see
    app/api/captures.py). It is not a security control — feed_token is what
    actually authorizes the push; a bogus/absent owner just leaves the
    resulting capture unowned (visible to everyone), same as before this
    feature existed.
    """
    if not _FEED_NAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session name (alphanumeric, hyphens, underscores; max 64 chars)",
        )

    # Feeds named ws-<ip>-<time> come from the Wireshark SSH-remote-capture
    # wrapper (scripts/pktpcap), which already gates on wireshark_capture_enabled
    # before it ever runs dumpcap. Everything else is a direct tshark/CLI push,
    # gated here on tshark_capture_enabled.
    if not name.startswith("ws-") and not await _get_setting("tshark_capture_enabled", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tshark/CLI captures are currently disabled in pktPCAP Live Feeds settings",
        )

    manager = request.app.state.feed_sessions
    session = await manager.get_or_create(name, request.client.host if request.client else "unknown")
    session.connected = True
    if owner is not None:
        session.owner_user_id = owner

    try:
        async for chunk in request.stream():
            if chunk:
                await session.append(chunk)
    finally:
        session.connected = False
        saved_filename = await save_feed_to_disk(session)
        if saved_filename:
            # Once it's a real file tracked in the captures table, the
            # in-memory session is redundant — drop it so a finished push
            # doesn't linger in "Active Feed Sessions" forever.
            await manager.delete(name)

    return {"ok": True, "bytes_received": session.bytes_received}


def _can_access_feed(owner_user_id: Optional[int], user: dict) -> bool:
    """Same ownership pattern as app/api/captures.py's _can_view/_can_manage:
    admins see/manage everything; a session with no owner (e.g. the
    Wireshark SSH wrapper, which has no pktPCAP user context to attribute a
    push to) stays accessible to anyone, matching pre-existing behavior for
    unowned captures; otherwise only the owner."""
    if user["role"] == "admin":
        return True
    if owner_user_id is None:
        return True
    return owner_user_id == user["id"]


@router.get("/feeds")
async def list_feeds(user: CurrentUser, request: Request):
    manager = request.app.state.feed_sessions
    sessions = await manager.list()
    return [s for s in sessions if _can_access_feed(s.get("owner_user_id"), user)]


@router.get("/feeds/{name}/download")
async def download_feed(name: str, user: CurrentUser, request: Request):
    manager = request.app.state.feed_sessions
    session = await manager.get(name)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not _can_access_feed(session.owner_user_id, user):
        raise HTTPException(status_code=403, detail="Only the owner or an admin can download this feed session")
    data = await session.get_bytes()
    if not data:
        raise HTTPException(status_code=404, detail="No data captured yet")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}.pcapng"'},
    )


@router.delete("/feeds/{name}")
async def delete_feed(name: str, user: CurrentUser, request: Request):
    manager = request.app.state.feed_sessions
    session = await manager.get(name)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if not _can_access_feed(session.owner_user_id, user):
        raise HTTPException(status_code=403, detail="Only the owner or an admin can delete this feed session")
    await manager.delete(name)
    return {"ok": True}
