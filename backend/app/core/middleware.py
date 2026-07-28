"""
ITAP — Security & Performance Middleware
Adds security headers, request ID injection, and performance timing.
"""
import time
import uuid
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger("itap.middleware")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds production-grade security headers to every response.
    Compliant with OWASP security header guidelines.
    """

    def __init__(self, app: ASGIApp, allowed_origins: list = None):
        super().__init__(app)
        self.allowed_origins = allowed_origins or ["http://localhost:5173"]

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws://localhost:* wss://localhost:*; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Injects a unique request ID for distributed tracing."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response: Response = await call_next(request)
        process_time = (time.perf_counter() - start_time) * 1000

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
        response.headers["X-Powered-By"] = "ITAP/2.0"

        # Log slow requests
        if process_time > 2000:
            logger.warning(
                f"SLOW REQUEST [{request_id}] {request.method} {request.url.path} "
                f"took {process_time:.0f}ms"
            )

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory sliding-window rate limiter.
    No Redis required — suitable for single-instance deployment.
    """

    def __init__(self, app: ASGIApp, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict = {}  # ip -> [timestamp, ...]

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check and docs
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old entries
        if client_ip in self._store:
            self._store[client_ip] = [t for t in self._store[client_ip] if t > window_start]
        else:
            self._store[client_ip] = []

        if len(self._store[client_ip]) >= self.max_requests:
            from fastapi.responses import JSONResponse
            retry_after = int(self.window_seconds - (now - self._store[client_ip][0]))
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "retry_after_seconds": max(retry_after, 1),
                },
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        self._store[client_ip].append(now)
        return await call_next(request)
