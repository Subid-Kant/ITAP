"""
ITAP — Integrated Threat Assessment Platform
An Autonomous Multi-Vector Cyber Threat Intelligence, 
Prediction & Incident Response Platform.

"Advanced Intelligence, Integrated Defence."

Authors: Subid Kant & Sparsh Sant Lal
SRMCEM Lucknow | B.Tech Final Year 2025-26 | Cyber Security (CY)
"""
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.db.database import init_db
from app.api.routes.api import router as api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("itap")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager."""
    logger.info("=" * 60)
    logger.info("  ITAP — Starting Up")
    logger.info("  Integrated Threat Assessment Platform")
    logger.info("=" * 60)
    
    # Initialize database
    await init_db()
    logger.info("✓ Database initialized")
    logger.info("✓ OSINT services ready")
    logger.info("✓ ML engine ready")
    logger.info("✓ Threat intelligence core ready")
    logger.info("✓ Response engine ready")
    logger.info(f"✓ API docs: http://localhost:{settings.PORT}/docs")
    logger.info(f"✓ Dashboard: http://localhost:{settings.PORT}")
    logger.info("=" * 60)
    
    yield
    
    logger.info("ITAP — Shutting Down")


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware (allow React frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes
app.include_router(api_router, prefix="/api/v1")

# Serve React frontend static files
FRONTEND_BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend", "dist")

if os.path.exists(FRONTEND_BUILD):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_BUILD, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve React SPA for any non-API route."""
        file_path = os.path.join(FRONTEND_BUILD, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_BUILD, "index.html"))
else:
    @app.get("/")
    async def root():
        return {
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "tagline": "Advanced Intelligence, Integrated Defence.",
            "status": "operational",
            "docs": "/docs",
            "api": "/api/v1",
            "dashboard": "Build frontend with: cd frontend && npm run build"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
