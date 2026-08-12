"""
pktPCAP — FastAPI application entry point.
"""
from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import init_db, seed_admin

# -- Routers -------------------------------------------------------------------
from app.api import (
    auth,
    users,
    settings as settings_router,
    system as system_router,
    logs as logs_router,
    integrations as integrations_router,
    suite as suite_router,
    user_api_keys as user_api_keys_router,
    ip_info as ip_info_router,
    mxtoolbox as mxtoolbox_router,
    ai as ai_router,
    widgets as widgets_router,
    docs as docs_router,
)

settings = get_settings()
log = logging.getLogger("pktpcap")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup ---------------------------------------------------------------
    from app.logging_handler import SQLiteLogHandler
    _log_handler = SQLiteLogHandler(db_path=settings.db_path)
    _log_handler.attach_to_root_logger("pktpcap")

    log.info("pktPCAP starting up")
    # Ship our own logs to pktLog if configured.
    try:
        import json as _json, logging as _logging
        import aiosqlite as _aio
        _fwd: dict = {}
        async with _aio.connect(settings.db_path) as _db:
            async with _db.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'log_forward_%'"
            ) as _cur:
                for _k, _v in await _cur.fetchall():
                    try:
                        _fwd[_k] = _json.loads(_v)
                    except Exception:
                        _fwd[_k] = _v
        if _fwd.get("log_forward_enabled"):
            from app.log_forward import configure_forwarding
            configure_forwarding(
                enabled=True,
                host=str(_fwd.get("log_forward_host") or ""),
                port=int(_fwd.get("log_forward_port") or 5514),
                protocol=str(_fwd.get("log_forward_protocol") or "udp"),
                level=getattr(_logging, str(_fwd.get("log_forward_level") or "INFO"), _logging.INFO),
                app_name=str(_fwd.get("log_forward_app_name") or "pktpcap"),
            )
    except Exception as _e:
        log.warning(f"Log forwarding setup skipped: {_e}")

    await init_db()
    log.info("Database migrations applied")

    await seed_admin()
    log.info("Admin seed check complete")

    from app.backup import BackupScheduler
    backup_scheduler = BackupScheduler()
    await backup_scheduler.start()
    log.info("Backup scheduler started")

    from app.retention import CaptureRetention
    capture_retention = CaptureRetention()
    await capture_retention.start()

    # Capture-domain startup (app/capture/*) doesn't exist until Stage 2 —
    # guarded the same way as the router registration below, so Stage 1 can
    # be curl-tested standalone before Stage 2 lands.
    reconcile_task = None
    try:
        from app.capture.feed_sessions import FeedSessionManager
        app.state.feed_sessions = FeedSessionManager()
        log.info("Feed session manager started (in-memory, single-worker)")

        from app.capture.reconcile import ReconcileTask
        reconcile_task = ReconcileTask()
        await reconcile_task.start()
        log.info("Capture reconciliation task started")
    except ImportError:
        log.warning("app.capture not present yet — feed/capture startup skipped (expected before Stage 2)")

    yield

    # -- Shutdown ----------------------------------------------------------------
    log.info("pktPCAP shutting down")
    if reconcile_task is not None:
        await reconcile_task.stop()
    await backup_scheduler.stop()
    _log_handler.stop()
    log.info("Shutdown complete")


# -- App -------------------------------------------------------------------------

app = FastAPI(
    title="pktPCAP",
    description="Packet capture and analysis for the pkt suite",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# -- Middleware --------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- API Routers -----------------------------------------------------------------

app.include_router(auth.router,             prefix="/api/auth",         tags=["auth"])
app.include_router(users.router,            prefix="/api/users",        tags=["users"])
app.include_router(logs_router.router,      prefix="/api/logs",         tags=["logs"])
app.include_router(integrations_router.router, prefix="/api/integrations", tags=["integrations"])
app.include_router(settings_router.router,  prefix="/api/settings",     tags=["settings"])
app.include_router(system_router.router,    prefix="/api/system",       tags=["system"])
app.include_router(suite_router.router,     prefix="/api/suite",        tags=["suite"])
app.include_router(user_api_keys_router.router, prefix="/api/user-api-keys", tags=["user-api-keys"])
app.include_router(ip_info_router.router,   prefix="/api/ip-info",      tags=["ip-info"])
app.include_router(mxtoolbox_router.router, prefix="/api/mxtoolbox",    tags=["mxtoolbox"])
app.include_router(ai_router.router,         prefix="/api/ai",           tags=["ai"])
app.include_router(widgets_router.router,    prefix="/api/widgets",      tags=["widgets"])
app.include_router(docs_router.router,       prefix="/api/docs-content", tags=["docs"])

# Capture-domain routers (feeds/captures) are registered lazily below —
# app/capture/* doesn't exist until Stage 2. Importing it at module load
# time here (rather than at the top of the file with everything else) lets
# Stage 1 be curl-tested standalone before Stage 2 lands.
try:
    from app.api import feeds as feeds_router, captures as captures_router
    app.include_router(feeds_router.router,     prefix="/api",              tags=["feeds"])
    app.include_router(captures_router.router,  prefix="/api/captures",     tags=["captures"])
except ImportError:
    log.warning("app.api.feeds/captures not present yet — capture endpoints unavailable (expected before Stage 2)")

# -- Health check ------------------------------------------------------------------

@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "version": "0.1.0"}

# -- Serve React frontend (production build) ---------------------------------------
_frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if _frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(_frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(request: Request, full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        # Normalize-then-prefix-check (CodeQL's own documented pattern for
        # py/path-injection) rather than pathlib's resolve()/is_relative_to,
        # which its Python taint tracker doesn't recognise as a sanitizer.
        _dist_root = os.path.normpath(str(_frontend_dist))
        _candidate = os.path.normpath(os.path.join(_dist_root, full_path))
        if not (_candidate == _dist_root or _candidate.startswith(_dist_root + os.sep)):
            # Path traversal — this handler is unauthenticated and config.yaml
            # sits two levels above dist, so "../../config.yaml" previously
            # returned the JWT signing key and the credential encryption key.
            raise HTTPException(status_code=404, detail="Not found")
        static_file = Path(_candidate)
        if static_file.exists() and static_file.is_file():
            return FileResponse(str(static_file))
        index = _frontend_dist / "index.html"
        response = FileResponse(str(index))
        # pktHub suite-token bootstrap — set sso cookies so React logs in automatically
        _cfg = settings
        _suite_tk = request.headers.get("x-suite-token", "")
        if _suite_tk and _cfg.suite_token and _suite_tk == _cfg.suite_token:
            from datetime import datetime, timedelta, timezone
            from jose import jwt as _jose_jwt
            from app.dependencies import _SUITE_ROLE_MAP
            _hub_user = request.headers.get("x-suite-user", "hub_user")
            _hub_role = request.headers.get("x-suite-role", "viewer")
            _local_role = _SUITE_ROLE_MAP.get(_hub_role, "viewer")
            _expire = datetime.now(tz=timezone.utc) + timedelta(hours=8)
            _payload = {"sub": "0", "role": _local_role, "exp": _expire, "type": "access"}
            _jwt = _jose_jwt.encode(_payload, _cfg.secret_key, algorithm=_cfg.algorithm)
            response.set_cookie("sso_access_token", _jwt,       max_age=60, httponly=False, samesite="lax")
            response.set_cookie("sso_role",         _local_role, max_age=60, httponly=False, samesite="lax")
        return response
