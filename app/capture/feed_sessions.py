"""
app/capture/feed_sessions.py
-----------------------------
In-memory buffer for a live pcapng stream pushed from a remote tshark/
Wireshark host. Async reimplementation of the old Flask app's synchronous
FeedSession/threading.Lock design — same 200MB cap and truncation behavior,
just safe under FastAPI/uvicorn's event loop instead of a WSGI thread pool.

IMPORTANT: this only works correctly with a single uvicorn worker (see
app/config.py's `workers` field and app/server.py). Feed sessions live in
this process's memory — a multi-worker deployment would silently split
ingest/list/download across separate processes and lose in-progress
captures. Do not raise workers above 1 without redesigning this to share
state across processes (e.g. moving buffers to disk or a shared cache).
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional


class FeedSession:
    """Buffers a live pcapng stream pushed from a remote tshark/Wireshark host."""
    MAX_BYTES = 200 * 1024 * 1024  # 200 MB per session

    def __init__(self, name: str, remote_addr: str):
        self.name = name
        self.remote_addr = remote_addr
        self.created_at = time.time()
        self.last_seen = time.time()
        self.connected = False
        self.bytes_received = 0
        self.truncated = False
        self._buf = bytearray()
        self._lock = asyncio.Lock()
        # Set from the optional ?owner=<user_id> query param on the ingest
        # POST — the push itself is authenticated by feed_token, not a user
        # login, so this is just bookkeeping for the captures-sharing
        # feature (whose capture this becomes once persisted), not a
        # security boundary. None for pushes that don't supply it (e.g. the
        # Wireshark SSH wrapper script, which has no pktPCAP user context at
        # all — those stay unowned and visible to everyone, same as before
        # this feature existed).
        self.owner_user_id: Optional[int] = None

    async def append(self, data: bytes) -> None:
        async with self._lock:
            self.last_seen = time.time()
            self.bytes_received += len(data)
            remaining = self.MAX_BYTES - len(self._buf)
            if remaining > 0:
                self._buf.extend(data[:remaining])
                if len(data) > remaining:
                    self.truncated = True
            else:
                self.truncated = True

    async def get_bytes(self) -> bytes:
        async with self._lock:
            return bytes(self._buf)

    async def to_dict(self) -> dict:
        async with self._lock:
            return {
                "name": self.name,
                "remote_addr": self.remote_addr,
                "connected": self.connected,
                "created_at": self.created_at,
                "last_seen": self.last_seen,
                "bytes_buffered": len(self._buf),
                "bytes_received": self.bytes_received,
                "duration": self.last_seen - self.created_at,
                "truncated": self.truncated,
                "owner_user_id": self.owner_user_id,
            }


class FeedSessionManager:
    """Owns every live FeedSession. One instance lives at app.state.feed_sessions,
    created in app/main.py's lifespan startup."""

    def __init__(self) -> None:
        self._sessions: dict[str, FeedSession] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(self, name: str, remote_addr: str) -> FeedSession:
        async with self._lock:
            if name not in self._sessions:
                self._sessions[name] = FeedSession(name, remote_addr)
            return self._sessions[name]

    async def get(self, name: str) -> Optional[FeedSession]:
        async with self._lock:
            return self._sessions.get(name)

    async def delete(self, name: str) -> None:
        async with self._lock:
            self._sessions.pop(name, None)

    async def list(self) -> list[dict]:
        async with self._lock:
            sessions = list(self._sessions.values())
        out = [await s.to_dict() for s in sessions]
        out.sort(key=lambda s: (not s["connected"], -s["last_seen"]))
        return out
