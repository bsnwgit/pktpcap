"""
pktPCAP — Widget endpoints for pktHub NOC Builder integration.

Manifest: GET /api/widgets/manifest  → list of widget definitions
Views:    GET /api/widgets/{id}      → server-rendered HTML page (iframe target)

pktPCAP has no alerting subsystem (no alert_events/alert_rules tables), so
unlike sibling apps this manifest has no "Active Alerts" widget.
"""
from __future__ import annotations

import html
from contextvars import ContextVar

import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.dependencies import require_suite_token

# These views are embedded as unauthenticated iframes by pktHub's NOC Builder,
# so they can't require a login session — but they do render internal capture
# and feed data, so every route on this router requires a valid X-Suite-Token
# (the trusted-proxy secret pktHub already sends on every proxied request).
# ── Refresh interval ──────────────────────────────────────────────────────────
# pktHub's Settings → NOC → "Widget refresh" governs how often a tile reloads
# itself. It arrives as ?refresh=<seconds> on the widget URL; captured here as a
# router dependency so the ~150 view functions need no signature change.
_REFRESH: ContextVar = ContextVar("widget_refresh", default=30)


async def _capture_refresh(request: Request) -> None:
    raw = request.query_params.get("refresh")
    try:
        _REFRESH.set(max(5, min(int(raw), 3600)) if raw else 30)
    except (TypeError, ValueError):
        _REFRESH.set(30)


router = APIRouter(dependencies=[Depends(_capture_refresh), Depends(require_suite_token)])
_s     = get_settings()
_DB    = _s.db_path

# ── Manifest ──────────────────────────────────────────────────────────────────
# `category` groups these in pktHub's NOC library picker. Every data surface the
# app renders in its own UI should have an entry here — the NOC builder can only
# offer what this list declares.
_WINDOW_PARAM = {
    "key": "days", "label": "Window", "type": "select",
    "options": [{"value": "7", "label": "7 days"}, {"value": "14", "label": "14 days"},
                {"value": "30", "label": "30 days"}, {"value": "90", "label": "90 days"}],
}

MANIFEST = [
    # ── Overview ──────────────────────────────────────────────────────────────
    {
        "id": "capture_summary", "title": "Capture Summary", "category": "Overview",
        "description": "Capture counts by status and total stored volume",
        "view_path": "/api/widgets/capture_summary",
        "default_w": 560, "default_h": 200, "min_w": 300, "min_h": 150,
    },
    {
        "id": "capture_storage", "title": "Capture Storage", "category": "Overview",
        "description": "Total saved capture count and disk usage",
        "view_path": "/api/widgets/capture_storage",
        "default_w": 400, "default_h": 220, "min_w": 260, "min_h": 160,
    },
    {
        "id": "captures_by_source", "title": "Captures by Source", "category": "Overview",
        "description": "Capture distribution across tshark, Wireshark and upload",
        "view_path": "/api/widgets/captures_by_source",
        "default_w": 440, "default_h": 280, "min_w": 260, "min_h": 170,
    },

    # ── Captures ──────────────────────────────────────────────────────────────
    {
        "id": "recent_captures", "title": "Recent Captures", "category": "Captures",
        "description": "Most recent capture sessions and their status",
        "view_path": "/api/widgets/recent_captures",
        "default_w": 640, "default_h": 380, "min_w": 340, "min_h": 220,
    },
    {
        "id": "largest_captures", "title": "Largest Captures", "category": "Captures",
        "description": "Biggest saved captures by file size",
        "view_path": "/api/widgets/largest_captures",
        "default_w": 600, "default_h": 340, "min_w": 320, "min_h": 200,
    },
    {
        "id": "failed_captures", "title": "Failed Captures", "category": "Captures",
        "description": "Captures that failed to save or have gone missing on disk",
        "view_path": "/api/widgets/failed_captures",
        "default_w": 640, "default_h": 340, "min_w": 320, "min_h": 200,
    },
    {
        "id": "top_sessions", "title": "Top Sessions", "category": "Captures",
        "description": "Feed sessions producing the most capture volume",
        "view_path": "/api/widgets/top_sessions",
        "default_w": 560, "default_h": 340, "min_w": 300, "min_h": 200,
    },

    # ── Trends (charts) ───────────────────────────────────────────────────────
    {
        "id": "capture_trend", "title": "Capture Trend", "category": "Trends",
        "description": "Captures saved per day",
        "view_path": "/api/widgets/capture_trend",
        "default_w": 620, "default_h": 300, "min_w": 300, "min_h": 170,
        "params": [_WINDOW_PARAM],
    },
    {
        "id": "volume_trend", "title": "Capture Volume Trend", "category": "Trends",
        "description": "Capture bytes written per day",
        "view_path": "/api/widgets/volume_trend",
        "default_w": 620, "default_h": 300, "min_w": 300, "min_h": 170,
        "params": [_WINDOW_PARAM],
    },

    # ── Live Feeds ────────────────────────────────────────────────────────────
    {
        "id": "live_feed_sessions", "title": "Live Feed Sessions", "category": "Live Feeds",
        "description": "Currently active tshark/Wireshark ingest feeds",
        "view_path": "/api/widgets/live_feed_sessions",
        "default_w": 640, "default_h": 320, "min_w": 320, "min_h": 200,
    },
]


@router.get("/manifest")
async def widget_manifest():
    return MANIFEST



# ── Widget states ──────────────────────────────────────────────────────────────
# A blank tile on a wallboard reads as "all quiet", so the three reasons a widget
# can show nothing must look different from each other:
#   empty — the query ran and there genuinely is nothing
#   cfg   — the widget needs a param chosen in the NOC editor before it can run
#   err   — the query failed; this must never be mistaken for "nothing to report"
# Query helpers record failures here rather than swallowing them; _page() renders
# the error state instead of whatever half-built body the caller produced. The
# ContextVar is per-request: each request runs in its own task context.
_WIDGET_ERR: ContextVar = ContextVar("widget_err", default=None)


def _note_err(exc: BaseException) -> None:
    _WIDGET_ERR.set(f"{type(exc).__name__}: {exc}"[:200])


def _state(kind: str, msg: str, sub: str = "") -> str:
    icon = {"empty": "○", "cfg": "⚙", "err": "⚠"}.get(kind, "○")
    sub_html = f'<div class="state-sub">{html.escape(str(sub))}</div>' if sub else ""
    return (f'<div class="state state-{kind}"><div class="state-icon">{icon}</div>'
            f'<div class="state-msg">{html.escape(str(msg))}</div>{sub_html}</div>')


def _empty(msg: str) -> str:
    return _state("empty", msg)


def _needs(msg: str) -> str:
    """The widget is fine — it is waiting on a filter the NOC editor must set."""
    return _state("cfg", msg, "Select it in the widget's Filters panel")


# ── Shared page shell ───────────────────────────────────────────────────────────
def _page(title: str, body: str) -> str:
    # Widget titles carry device/metric/subnet names chosen in the NOC editor
    # and read back from device data, and these pages render on an
    # unauthenticated display URL — escape before interpolating.
    title = html.escape(str(title))
    # A failed query leaves a body saying "nothing here" — which is a lie.
    _err = _WIDGET_ERR.get()
    if _err:
        body = _state("err", "Widget unavailable", _err)
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#04060a;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;font-size:13px;height:100vh;overflow:hidden;display:flex;flex-direction:column}}
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
.bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
.bar-lbl{{font-size:11px;color:#94a3b8;width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar-trk{{flex:1;background:#1e293b;border-radius:3px;height:8px;overflow:hidden}}
.bar-fill{{height:8px;border-radius:3px;background:#a78bfa}}
.bar-val{{font-size:10px;color:#475569;width:70px;text-align:right;flex-shrink:0}}
.chart-wrap{{width:100%;height:100%;min-height:90px;display:flex;flex-direction:column}}
.chart-meta{{display:flex;gap:12px;font-size:10px;color:#475569;margin-bottom:6px;flex-wrap:wrap}}
.chart-meta b{{color:#94a3b8;font-weight:600}}
.chart-svg{{flex:1;width:100%;min-height:0}}
.legend{{display:flex;gap:12px;font-size:10px;color:#94a3b8;margin-top:6px;flex-wrap:wrap}}
.legend i{{width:8px;height:2px;display:inline-block;margin-right:4px;vertical-align:middle}}
.state{{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:80px;text-align:center;padding:18px;gap:5px}}
.state-icon{{font-size:17px;line-height:1;opacity:0.85}}
.state-msg{{font-size:12px;font-weight:500}}
.state-sub{{font-size:10px;color:#64748b;max-width:92%;word-break:break-word}}
.state-empty{{color:#64748b}}
.state-cfg{{color:#fbbf24}}
.state-err{{color:#f87171}}
</style>
<script>setTimeout(()=>location.reload(),{_REFRESH.get() * 1000})</script>
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


def _fmt_n(n) -> str:
    try:
        return f"{float(n or 0):.0f}"
    except (TypeError, ValueError):
        return "—"


# ── Query helper ────────────────────────────────────────────────────────────────
async def _rows(sql: str, params: tuple = ()) -> list[dict]:
    try:
        async with aiosqlite.connect(_DB) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, params) as cur:
                return [dict(r) for r in await cur.fetchall()]
    except Exception as exc:
        _note_err(exc)
        return []


# ── Tiles / bars ────────────────────────────────────────────────────────────────
def _tiles(pairs) -> str:
    return '<div class="tile-row">' + "".join(
        f'<div class="tile"><div class="tile-label">{html.escape(str(label))}</div>'
        f'<div class="tile-value">{html.escape(str(value))}</div></div>'
        for label, value in pairs
    ) + "</div>"


def _bars(rows, color: str = "#a78bfa") -> str:
    """rows = [(label, numeric_value, display_value)] — scaled to the largest."""
    peak = max((r[1] or 0) for r in rows) if rows else 0
    return "".join(
        f'<div class="bar-row"><div class="bar-lbl" title="{html.escape(str(lbl))}">{html.escape(str(lbl))}</div>'
        f'<div class="bar-trk"><div class="bar-fill" style="width:{(val / peak * 100) if peak else 0:.1f}%;background:{color}"></div></div>'
        f'<div class="bar-val">{html.escape(str(disp))}</div></div>'
        for lbl, val, disp in rows
    )


# ── Inline SVG line chart ───────────────────────────────────────────────────────
# Server-rendered so the iframe stays dependency-free — pktPCAP ships no charting
# library to these views, and the NOC display must render without network access
# to anything but this app.
_SERIES_COLORS = ("#a78bfa", "#60a5fa", "#4ade80", "#f87171", "#fbbf24")


def _line_chart(series, fmt=_fmt_n, height: int = 120) -> str:
    """series = [(label, [float, ...])] — equal-length samples, oldest first."""
    series = [(lbl, [v for v in vals if v is not None]) for lbl, vals in series]
    series = [(lbl, vals) for lbl, vals in series if len(vals) >= 2]
    if not series:
        return _empty('No samples in window')

    W, H, PAD = 600, height, 4
    lo = min(min(v) for _, v in series)
    hi = max(max(v) for _, v in series)
    span = (hi - lo) or 1.0

    def _y(v: float) -> float:
        return PAD + (H - 2 * PAD) * (1 - (v - lo) / span)

    paths, legend = [], []
    for i, (lbl, vals) in enumerate(series):
        color = _SERIES_COLORS[i % len(_SERIES_COLORS)]
        step  = W / (len(vals) - 1)
        pts   = [(j * step, _y(v)) for j, v in enumerate(vals)]
        line  = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        area  = f"{line} L{W:.1f},{H} L0,{H} Z"
        paths.append(
            f'<path d="{area}" fill="{color}" opacity="0.10"/>'
            f'<path d="{line}" fill="none" stroke="{color}" stroke-width="1.5" '
            f'stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>'
        )
        legend.append(
            f'<span><i style="background:{color}"></i>{html.escape(str(lbl))} '
            f'<b>{html.escape(fmt(vals[-1]))}</b></span>'
        )

    meta = (f'<div class="chart-meta"><span>min <b>{html.escape(fmt(lo))}</b></span>'
            f'<span>max <b>{html.escape(fmt(hi))}</b></span>'
            f'<span>samples <b>{max(len(v) for _, v in series)}</b></span></div>')
    return (
        f'<div class="chart-wrap">{meta}'
        f'<svg class="chart-svg" viewBox="0 0 {W} {H}" preserveAspectRatio="none" '
        f'xmlns="http://www.w3.org/2000/svg">{"".join(paths)}</svg>'
        f'<div class="legend">{"".join(legend)}</div></div>'
    )


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
    except Exception as exc:
        _note_err(exc)

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
        body = _empty('No captures saved yet')
    return HTMLResponse(_page("Recent Captures", body))


# ── Live Feed Sessions widget ─────────────────────────────────────────────────
@router.get("/live_feed_sessions", response_class=HTMLResponse, include_in_schema=False)
async def widget_live_feed_sessions(request: Request):
    sessions = []
    try:
        manager = request.app.state.feed_sessions
        sessions = await manager.list()
    except Exception as exc:
        _note_err(exc)
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
        body = _empty('No active feed sessions')
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
    except Exception as exc:
        _note_err(exc)

    body = (
        '<div class="tile-row">'
        f'<div class="tile"><div class="tile-label">Saved Captures</div><div class="tile-value">{count}</div></div>'
        f'<div class="tile"><div class="tile-label">Total Size</div><div class="tile-value">{_fmt_bytes(total_bytes)}</div></div>'
        "</div>"
    )
    return HTMLResponse(_page("Capture Storage", body))


# ── Capture Summary widget ────────────────────────────────────────────────────
@router.get("/capture_summary", response_class=HTMLResponse, include_in_schema=False)
async def widget_capture_summary():
    rows = await _rows(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status='saved'   THEN 1 ELSE 0 END) AS saved,
                  SUM(CASE WHEN status='failed'  THEN 1 ELSE 0 END) AS failed,
                  SUM(CASE WHEN status='missing' THEN 1 ELSE 0 END) AS missing,
                  COALESCE(SUM(size_bytes),0) AS bytes
           FROM captures"""
    )
    r = rows[0] if rows else {}
    body = _tiles([
        ("Captures", r.get("total")   or 0),
        ("Saved",    r.get("saved")   or 0),
        ("Failed",   r.get("failed")  or 0),
        ("Missing",  r.get("missing") or 0),
        ("Volume",   _fmt_bytes(r.get("bytes"))),
    ])
    return HTMLResponse(_page("Capture Summary", body))


# ── Captures by Source widget ─────────────────────────────────────────────────
@router.get("/captures_by_source", response_class=HTMLResponse, include_in_schema=False)
async def widget_captures_by_source():
    rows = await _rows(
        "SELECT COALESCE(NULLIF(source,''),'unknown') AS source, COUNT(*) AS n, "
        "COALESCE(SUM(size_bytes),0) AS bytes FROM captures GROUP BY source ORDER BY n DESC"
    )
    body = _bars([
        (r["source"], r["n"], f"{r['n']} · {_fmt_bytes(r['bytes'])}") for r in rows
    ]) if rows else _empty('No captures saved yet')
    return HTMLResponse(_page("Captures by Source", body))


# ── Largest Captures widget ───────────────────────────────────────────────────
@router.get("/largest_captures", response_class=HTMLResponse, include_in_schema=False)
async def widget_largest_captures():
    rows = await _rows(
        "SELECT filename, session_name, source, size_bytes, created_at FROM captures "
        "WHERE status='saved' AND size_bytes IS NOT NULL ORDER BY size_bytes DESC LIMIT 30"
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['filename']))}</td>"
            f"<td>{html.escape(str(r.get('session_name') or '—'))}</td>"
            f"<td>{html.escape(str(r.get('source') or ''))}</td>"
            f"<td>{_fmt_bytes(r['size_bytes'])}</td>"
            f"<td>{html.escape(str(r['created_at'])[:19].replace('T',' '))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>File</th><th>Session</th><th>Source</th>"
                "<th>Size</th><th>Created</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No captures have been written to disk')
    return HTMLResponse(_page("Largest Captures", body))


# ── Failed Captures widget ────────────────────────────────────────────────────
@router.get("/failed_captures", response_class=HTMLResponse, include_in_schema=False)
async def widget_failed_captures():
    rows = await _rows(
        "SELECT filename, session_name, source, status, created_at FROM captures "
        "WHERE status IN ('failed','missing') ORDER BY created_at DESC LIMIT 40"
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['filename']))}</td>"
            f"<td>{html.escape(str(r.get('session_name') or '—'))}</td>"
            f"<td>{_status_badge(r['status'])}</td>"
            f"<td>{html.escape(str(r['created_at'])[:19].replace('T',' '))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>File</th><th>Session</th><th>Status</th><th>Created</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('Every capture saved cleanly')
    return HTMLResponse(_page("Failed Captures", body))


# ── Top Sessions widget ───────────────────────────────────────────────────────
@router.get("/top_sessions", response_class=HTMLResponse, include_in_schema=False)
async def widget_top_sessions():
    # Direct uploads carry no session name; they are not a feed and would
    # otherwise all collapse into one meaningless bucket.
    rows = await _rows(
        """SELECT session_name, COUNT(*) AS n, COALESCE(SUM(size_bytes),0) AS bytes
           FROM captures WHERE session_name IS NOT NULL AND session_name <> ''
           GROUP BY session_name ORDER BY bytes DESC LIMIT 25"""
    )
    body = _bars([
        (r["session_name"], float(r["bytes"]), f"{r['n']} · {_fmt_bytes(r['bytes'])}") for r in rows
    ]) if rows else _empty('No capture has come from a named feed')
    return HTMLResponse(_page("Top Sessions", body))


# ── Capture / Volume Trend widgets (charts) ───────────────────────────────────
async def _daily(days: int) -> list[dict]:
    days = max(1, min(int(days or 7), 365))
    return await _rows(
        """SELECT date(created_at) AS day, COUNT(*) AS n, COALESCE(SUM(size_bytes),0) AS bytes
           FROM captures WHERE created_at >= date('now', ?)
           GROUP BY day ORDER BY day ASC""",
        (f"-{days} days",),
    )


@router.get("/capture_trend", response_class=HTMLResponse, include_in_schema=False)
async def widget_capture_trend(days: int = 7):
    rows = await _daily(days)
    body = _line_chart([("Captures", [r["n"] for r in rows])])
    return HTMLResponse(_page(f"Capture Trend — last {days}d", body))


@router.get("/volume_trend", response_class=HTMLResponse, include_in_schema=False)
async def widget_volume_trend(days: int = 7):
    rows = await _daily(days)
    body = _line_chart([("Volume", [r["bytes"] for r in rows])], fmt=_fmt_bytes)
    return HTMLResponse(_page(f"Capture Volume — last {days}d", body))
