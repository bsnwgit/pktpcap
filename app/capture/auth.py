"""
Bearer-token auth for the machine-to-machine feed ingest endpoint
(POST /api/feed/{name}). This is NOT a logged-in user — it's tshark, the
Wireshark SSH-remote-capture wrapper script, or any other curl-based
pusher — so it does not go through app/dependencies.py's JWT/suite-token
CurrentUser dependency. It checks the Authorization header against the
`feed_token` setting instead, read fresh from SQLite on every call (no
caching) so a token rotated in Settings takes effect immediately.
"""
from __future__ import annotations

import json

import aiosqlite
from fastapi import HTTPException, Request, status

from app.database import DB_PATH


async def _get_feed_token() -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key = 'feed_token'") as cur:
            row = await cur.fetchone()
    if not row:
        return ""
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return row[0]


async def require_feed_token(request: Request) -> None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized — include Authorization: Bearer <token> header",
        )
    token = auth[7:].strip()
    expected = await _get_feed_token()
    if not token or not expected or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized — include Authorization: Bearer <token> header",
        )
