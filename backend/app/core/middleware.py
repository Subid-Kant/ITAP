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

from app.core.config import settings

logger = logging.getLogger("itap.middleware")


def _connect_sources() -> str:
    """Origins the SPA may fetch/connect to, derived from configuration.

    This used to be the literal ``ws://localhost:* wss://localhost:*``, which
    allowed any local port and covered no other deployment. In dev the Vite server
    (5173) talks straight to the API on 8000 and the live feed is a WebSocket, so
    both the configured origins and the http/https/ws/wss twins of the API origin
    are listed; the built SPA served from the same origin only needs 'self'.
    """
    sources = ["'self'"]
    sources.extend(settings.cors_origins)
    host = settings.HOST if settings.HOST not in ("0.0.0.0", "::", "") else "localhost"
    for scheme in ("http", "https", "ws", "wss"):
        sources.append(f"{scheme}://{host}:{settings.PORT}")
    return " ".join(dict.fromkeys(sources))


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
        # X-XSS-Protection is deprecated, ignored by current browsers, and its
        # legacy auditor was itself a source of bugs — it is no longer sent.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Content Security Policy — no 'unsafe-inline' / 'unsafe-eval' for scripts.
        # While those were present the policy permitted exactly the thing an XSS
        # payload needs, which is what made a token readable from localStorage
        # exploitable. The built SPA contains no inline <script>, no inline event
        # handlers and no inline style attributes, so 'self' is sufficient
        # (style-src still needs 'unsafe-inline' for React style={{...}} props).
        csp = (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            f"connect-src {_connect_sources()}; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
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
        # X-Powered-By used to advertise the stack ("ITAP/2.0") on every response;
        # that is free reconnaissance for no benefit, so it is gone.

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

    def __init__(self, app: ASGIApp, max_requests: int = 5000, window_seconds: int = 60):
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
        # Skip rate limiting for health check and API docs.
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        # Bypass rate limiting for localhost when explicitly allowed. This used to
        # be hardcoded, which made the limiter impossible to exercise in dev (and
        # meant /auth/login had no protection at all on loopback).
        if settings.RATE_LIMIT_ALLOW_LOCALHOST and client_ip in ("127.0.0.1", "::1", "localhost"):
            return await call_next(request)

        now = time.time()

        # Sliding window for this IP: drop its expired timestamps.
        attempts = [
            t for t in self._store.get(client_ip, []) if now - t < self.window_seconds
        ]

        if len(attempts) >= self.max_requests:
            from fastapi.responses import JSONResponse
            retry_after = max(int(self.window_seconds - (now - attempts[0])), 1)
            logger.warning(f"Rate limit exceeded for {client_ip}")
            self._store[client_ip] = attempts
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        attempts.append(now)
        self._store[client_ip] = attempts

        # Opportunistic sweep. `_store` gained one key per IP ever seen and never
        # released them; sweep once the dict is big enough for it to matter.
        if len(self._store) > 1024:
            for ip, stamps in list(self._store.items()):
                if not any(now - t < self.window_seconds for t in stamps):
                    self._store.pop(ip, None)

        return await call_next(request)
