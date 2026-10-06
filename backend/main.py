"""
ITAP — Main Application Entry Point v2.0
Production-ready FastAPI application with security middleware,
WebSocket support, and comprehensive startup validation.
"""
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.middleware import SecurityHeadersMiddleware, RequestIDMiddleware, RateLimitMiddleware
from app.db.database import init_db, async_session_factory
from sqlalchemy import update
from app.models.models import Target, Scan, Threat, Incident, AnomalyDetection
from app.api.routes.api import router as api_router
from app.api.routes.ws import manager as ws_manager
from app.services.monitoring.server_monitor import server_monitor
from app.services.monitoring.global_threat_feed import global_threat_feed
from app.services.monitoring.machine_scanner import machine_scanner

# ── Logging Configuration ──────────────────────────────────────────────────────
from app.core.logging_filters import install_secret_filter

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(name)-28s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Attached to the root logger so third-party libraries (aiohttp, httpx, uvicorn
# access logs) are covered as well as our own loggers.
install_secret_filter()
logger = logging.getLogger("itap")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager with proper startup/shutdown."""
    logger.info("=" * 70)
    logger.info("  ITAP v2.0 — Integrated Threat Assessment Platform")
    logger.info("  Advanced Intelligence, Integrated Defence.")
    logger.info(f"  Environment: {settings.ENVIRONMENT}")
    logger.info("=" * 70)

    await init_db()
    logger.info("✓ Database initialized and schema synchronized")

    # Optional Redis cache check (graceful fallback)
    try:
        from app.core.cache import health_check as redis_health
        redis_status = await redis_health()
        if redis_status["redis"] == "connected":
            logger.info(f"✓ Redis cache connected — 24h TTL scan caching ACTIVE (v{redis_status.get('version', '?')})")
        else:
            logger.info("⚠️  Redis not available — scan caching DISABLED (app will still work)")
    except Exception:
        logger.info("⚠️  Redis module not installed — scan caching DISABLED")

    logger.info(f"✓ CORS allowed origins: {settings.cors_origins}")
    logger.info(f"✓ Rate limit: {settings.RATE_LIMIT_REQUESTS} req/{settings.RATE_LIMIT_WINDOW_SECONDS}s per IP")
    logger.info("✓ Security middleware: headers, request-ID, rate-limiter")
    logger.info("✓ JWT authentication ready (HS256)")
    logger.info("✓ OSINT services: Shodan, VirusTotal, CVE/NVD, AlienVault OTX (deep per-service CVE analysis)")
    logger.info("✓ ML Engine: LSTM predictor, Autoencoder, Severity scorer")
    logger.info("✓ Threat Intelligence: MITRE ATT&CK, Kill-Chain, IOC")
    logger.info("✓ SOAR: Mock Firewall IP blocking (admin-only)")
    logger.info("✓ Response Engine: Playbook generator, Alert dispatcher")
    logger.info(f"✓ API docs: http://localhost:{settings.PORT}/docs")
    logger.info(f"✓ WebSocket: ws://localhost:{settings.PORT}/ws/live")
    
    # Start background monitors
    await server_monitor.start()
    await global_threat_feed.start()
    await machine_scanner.start()
    logger.info("✓ Machine Scanner: host IP detection + network threat analysis started")
    
    logger.info("=" * 70)

    yield

    # Stop background monitors gracefully
    await server_monitor.stop()
    await global_threat_feed.stop()
    await machine_scanner.stop()
    
    logger.info("ITAP — Graceful shutdown complete")


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Authentication", "description": "JWT login, refresh, and logout"},
        {"name": "Targets", "description": "Monitoring target management"},
        {"name": "OSINT Scanning", "description": "Layer 1: Multi-source intelligence collection"},
        {"name": "AI/ML Engine", "description": "Layer 2: Predictive threat analytics"},
        {"name": "Threat Intelligence", "description": "Layer 3: MITRE ATT&CK, Kill-Chain, IOC"},
        {"name": "Incident Response", "description": "Layer 4: Playbooks, alerts, remediation"},
        {"name": "Dashboard", "description": "Layer 5: SOC metrics and visualizations"},
        {"name": "Reports", "description": "Export and reporting"},
    ],
)

# ── Middleware Stack ──────────────────────────────────────────────────────────
# Starlette's add_middleware() *prepends*: the LAST call is the OUTERMOST layer.
# So the order below reads inside-out — CORS is added last and therefore wraps
# everything, including the security headers and the rate limiter. (The previous
# comment claimed "outermost first", which is the opposite of what happens and
# invites a future reorder that silently changes which layer sees the request.)
app.add_middleware(RateLimitMiddleware,
                   max_requests=settings.RATE_LIMIT_REQUESTS,
                   window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS)

app.add_middleware(SecurityHeadersMiddleware, allowed_origins=settings.cors_origins)

app.add_middleware(RequestIDMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"],
    expose_headers=["X-Request-ID", "X-Process-Time"],
)


# ── Custom Exception Handlers ─────────────────────────────────────────────────
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    errors = []
    for error in exc.errors():
        errors.append({
            "field": " → ".join(str(e) for e in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation failed", "errors": errors},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    # While debugging, returning a generic 500 hides the traceback that TestClient
    # would otherwise raise, which turns a two-minute fix into a log hunt. The
    # real client-facing behaviour is unchanged outside DEBUG.
    if settings.DEBUG:
        raise exc
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please check logs."},
    )


# ── API Routes ────────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for load balancers and Docker healthchecks."""
    from app.core.cache import health_check as redis_health
    try:
        redis_status = await redis_health()
    except Exception:
        redis_status = {"redis": "unavailable"}
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "cache": redis_status,
    }


# ── WebSocket Live Feed ───────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    Real-time threat event stream via WebSocket.
    Broadcasts new threats, scan completions, and system alerts.

    Requires authentication: the client's first frame must be
    ``{"type": "auth", "token": "<access token>"}``. Until that frame validates,
    the socket is only *pending* and receives no broadcasts (see ConnectionManager).
    """
    if not await ws_manager.connect(websocket):
        return
    if not await ws_manager.authenticate(websocket):
        return
    try:
        while True:
            # Keep connection alive — receive heartbeat pings from client
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket closed after error: {exc}")
        ws_manager.disconnect(websocket)


# ── Frontend SPA Serving ──────────────────────────────────────────────────────
# backend/main.py -> dirname is `backend/`, dirname again is the repo root. The
# previous version called dirname() three times, so this resolved to
# `<parent-of-repo>/frontend/dist`: never present, which silently disabled the SPA
# branch below (and with it the path-traversal guard that was added to it).
FRONTEND_BUILD = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "frontend", "dist"
)
FRONTEND_ASSETS = os.path.join(FRONTEND_BUILD, "assets")

if os.path.isdir(FRONTEND_BUILD):
    # Guard the mount too: StaticFiles(directory=...) raises on a missing directory,
    # which would take the whole app down just because a build has no assets/.
    if os.path.isdir(FRONTEND_ASSETS):
        app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """Serve React SPA — returns index.html for any non-API route.

        Security: the request-supplied path is confined to FRONTEND_BUILD.
        Without this containment, `/%2e%2e%2e%2e%2e%2e/etc/passwd` (or the
        Windows equivalent) escaped the web root and disclosed any file the
        server process can read, including backend/.env with live API keys.

        API and WebSocket paths are excluded from the catch-all: otherwise a
        mistyped `/api/v1/targts` answered 200 with an HTML page instead of 404,
        which hides real routing mistakes from both callers and tests.
        """
        if full_path.startswith(("api/", "ws/")):
            return JSONResponse(status_code=404, content={"detail": "Not found"})

        root = os.path.realpath(FRONTEND_BUILD)
        candidate = os.path.realpath(os.path.join(root, full_path))
        try:
            contained = os.path.commonpath([root, candidate]) == root
        except ValueError:
            # Different drives on Windows (e.g. C:\\ vs D:\\) -> not contained.
            contained = False
        if contained and candidate != root and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(root, "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "tagline": "Advanced Intelligence, Integrated Defence.",
            "status": "operational",
            "docs": "/docs",
            "api": "/api/v1",
            "websocket": "/ws/live",
            "dashboard": "Build frontend: cd frontend && npm run build",
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
        access_log=settings.DEBUG,
    )
