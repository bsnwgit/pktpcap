"""
pktPCAP — Widget endpoints for pktHub NOC Builder integration.

Manifest: GET /api/widgets/manifest  → list of widget definitions
Views:    GET /api/widgets/{id}      → server-rendered HTML page (iframe target)

pktPCAP has no alerting subsystem (no alert_events/alert_rules tables), so
unlike sibling apps this manifest has no "Active Alerts" widget.
"""
from __future__ import annotations

import html

import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.dependencies import require_suite_token

# These views are embedded as unauthenticated iframes by pktHub's NOC Builder,
# so they can't require a login session — but they do render internal capture
# and feed data, so every route on this router requires a valid X-Suite-Token
# (the trusted-proxy secret pktHub already sends on every proxied request).
router = APIRouter(dependencies=[Depends(require_suite_token)])
_s     = get_settings()
_DB    = _s.db_path

# ── Manifest ──────────────────────────────────────────────────────────────────
MANIFEST = [
    {
        "id": "recent_captures", "title": "Recent Captures",
        "description": "Most recent capture sessions and their status",
        "view_path": "/api/widgets/recent_captures",
        "default_w": 640, "default_h": 380, "min_w": 340, "min_h": 220,
    },
    {
        "id": "live_feed_sessions", "title": "Live Feed Sessions",
        "description": "Currently active tshark/Wireshark ingest feeds",
        "view_path": "/api/widgets/live_feed_sessions",
        "default_w": 640, "default_h": 320, "min_w": 320, "min_h": 200,
    },
    {
        "id": "capture_storage", "title": "Capture Storage",
        "description": "Total saved capture count and disk usage",
        "view_path": "/api/widgets/capture_storage",
        "default_w": 400, "default_h": 220, "min_w": 260, "min_h": 160,
    },
]


@router.get("/manifest")
async def widget_manifest():
    return MANIFEST


# ── Shared page shell ───────────────────────────────────────────────────────────
def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a1628;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;font-size:13px;height:100vh;overflow:hidden;display:flex;flex-direction:column}}
.hdr{{padding:8px 14px;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:8px;flex-shrink:0;height:36px}}
.hdr-dot{{width:6px;height:6px;border-radius:50%;background:#a78bfa;flex-shrink:0}}
.hdr-title{{font-size:11px;font-weight:600;color:#94a3b8;letter-spacing:0.03em}}
.content{{flex:1;overflow:auto;padding:12px}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;font-size:10px;color:#475569;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;padding:4px 8px;border-bottom:1px solid #1e293b}}
td{{padding:6px 8px;border-bottom:1px solid #0f172a;font-size:12px;color:#cbd5e1}}
tr:hover td{{background:#111827}}
.badge{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}}
.bg{{background:#052e16;color:#4ade80}}.br{{background:#3f1515;color:#f87171}}
.by{{background:#422006;color:#fbbf24}}.bn{{background:#1e293b;color:#64748b}}
.empty{{text-align:center;padding:40px;color:#334155;font-size:12px}}
.tile-row{{display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap}}
.tile{{flex:1;min-width:100px;background:#111827;border:1px solid #1e293b;border-radius:8px;padding:10px 12px}}
.tile-label{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:4px}}
.tile-value{{font-size:22px;font-weight:700;color:#e2e8f0}}
</style>
<script>setTimeout(()=>location.reload(),30000)</script>
</head><body>
<div class="hdr"><div class="hdr-dot"></div><div class="hdr-title">{title}</div></div>
<div class="content">{body}</div>
</body></html>"""


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s == "saved":
        return '<span class="badge bg">SAVED</span>'
    if s == "failed":
        return '<span class="badge br">FAILED</span>'
    if s == "missing":
        return '<span class="badge by">MISSING</span>'
    return f'<span class="badge bn">{html.escape((status or "UNKNOWN").upper())}</span>'


def _fmt_bytes(n) -> str:
    n = n or 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── Recent Captures widget ────────────────────────────────────────────────────
@router.get("/recent_captures", response_class=HTMLResponse, include_in_schema=False)
async def widget_recent_captures():
    rows = []
    try:
        async with aiosqlite.connect(_DB) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT session_name, source, size_bytes, status, created_at FROM captures "
                "ORDER BY created_at DESC LIMIT 40"
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
    except Exception:
        pass

    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['session_name']))}</td><td>{html.escape(str(r['source']))}</td>"
            f"<td>{_fmt_bytes(r['size_bytes'])}</td>"
            f"<td>{_status_badge(r['status'])}</td>"
            f"<td>{html.escape(str(r['created_at'])[:19].replace('T',' '))}</td></tr>"
            for r in rows
        )
        body = (
            "<table><thead><tr><th>Session</th><th>Source</th><th>Size</th><th>Status</th><th>Created</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>"
        )
    else:
        body = '<div class="empty">No captures yet</div>'
    return HTMLResponse(_page("Recent Captures", body))


# ── Live Feed Sessions widget ─────────────────────────────────────────────────
@router.get("/live_feed_sessions", response_class=HTMLResponse, include_in_schema=False)
async def widget_live_feed_sessions(request: Request):
    sessions = []
    try:
        manager = request.app.state.feed_sessions
        sessions = await manager.list()
    except Exception:
        sessions = []

    if sessions:
        parts = []
        for s in sessions:
            state_badge = '<span class="badge bg">LIVE</span>' if s.get("connected") else '<span class="badge bn">IDLE</span>'
            parts.append(
                f"<tr><td>{html.escape(str(s['name']))}</td><td>{html.escape(str(s.get('remote_addr') or ''))}</td>"
                f"<td>{state_badge}</td>"
                f"<td>{_fmt_bytes(s.get('bytes_received'))}</td></tr>"
            )
        trs = "".join(parts)
        body = (
            "<table><thead><tr><th>Feed</th><th>Source</th><th>State</th><th>Received</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>"
        )
    else:
        body = '<div class="empty">No active feed sessions</div>'
    return HTMLResponse(_page("Live Feed Sessions", body))


# ── Capture Storage widget ────────────────────────────────────────────────────
@router.get("/capture_storage", response_class=HTMLResponse, include_in_schema=False)
async def widget_capture_storage():
    total_bytes = 0
    count = 0
    try:
        async with aiosqlite.connect(_DB) as db:
            async with db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes),0) FROM captures WHERE status='saved'"
            ) as cur:
                row = await cur.fetchone()
                if row:
                    count, total_bytes = row
    except Exception:
        pass

    body = (
        '<div class="tile-row">'
        f'<div class="tile"><div class="tile-label">Saved Captures</div><div class="tile-value">{count}</div></div>'
        f'<div class="tile"><div class="tile-label">Total Size</div><div class="tile-value">{_fmt_bytes(total_bytes)}</div></div>'
        "</div>"
    )
    return HTMLResponse(_page("Capture Storage", body))
