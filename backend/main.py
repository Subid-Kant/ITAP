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
from app.db.database import init_db
from app.api.routes.api import router as api_router
from app.api.routes.ws import manager as ws_manager

# ── Logging Configuration ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(name)-28s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
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
    logger.info(f"✓ CORS allowed origins: {settings.cors_origins}")
    logger.info(f"✓ Rate limit: {settings.RATE_LIMIT_REQUESTS} req/{settings.RATE_LIMIT_WINDOW_SECONDS}s per IP")
    logger.info("✓ Security middleware: headers, request-ID, rate-limiter")
    logger.info("✓ JWT authentication ready (HS256)")
    logger.info("✓ OSINT services: Shodan, VirusTotal, CVE/NVD, AlienVault OTX")
    logger.info("✓ ML Engine: LSTM predictor, Autoencoder, Severity scorer")
    logger.info("✓ Threat Intelligence: MITRE ATT&CK, Kill-Chain, Threat DNA")
    logger.info("✓ Response Engine: Playbook generator, Alert dispatcher")
    logger.info(f"✓ API docs: http://localhost:{settings.PORT}/docs")
    logger.info(f"✓ WebSocket: ws://localhost:{settings.PORT}/ws/live")
    logger.info("=" * 70)

    yield

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

# ── Middleware Stack (order matters — outermost first) ────────────────────────
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
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


# ── WebSocket Live Feed ───────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    Real-time threat event stream via WebSocket.
    Broadcasts new threats, scan completions, and system alerts.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive — receive heartbeat pings from client
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Frontend SPA Serving ──────────────────────────────────────────────────────
FRONTEND_BUILD = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "frontend", "dist"
)

if os.path.exists(FRONTEND_BUILD):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_BUILD, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """Serve React SPA — returns index.html for any non-API route."""
        file_path = os.path.join(FRONTEND_BUILD, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_BUILD, "index.html"))
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
