"""
ITAP — Security & Authentication Core
JWT token management, password hashing, and FastAPI auth dependencies.
"""
import os
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.db.database import get_db

logger = logging.getLogger("itap.security")

bearer_scheme = HTTPBearer(auto_error=False)


# ─────────────────────────────────────────────
# Password Utilities
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its hash.

    bcrypt raises ValueError on a malformed/truncated hash. Uncaught, that turned
    a bad stored hash into a 500 on /auth/login instead of a failed login, so treat
    "cannot check this hash" as "does not match".
    """
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        logger.error("Malformed password hash encountered — refusing the login attempt.")
        return False


# ─────────────────────────────────────────────
# Login Throttling
# ─────────────────────────────────────────────
# In-memory sliding window, keyed by "<username>|<client-ip>". Deliberately
# independent of RateLimitMiddleware: that limiter skips localhost entirely (dev
# convenience) and caps a whole IP, so it can never protect a single account
# against password guessing. In-process, like the rest of the dev-phase state;
# a multi-worker deployment needs Redis/slowapi here.

_FAILED_LOGINS: Dict[str, list] = {}
_FAILED_LOGINS_LOCK = threading.Lock()

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300


def guard_login(key: str) -> None:
    """Raise 429 when ``key`` has already failed too often inside the window."""
    now = time.time()
    with _FAILED_LOGINS_LOCK:
        attempts = [
            t for t in _FAILED_LOGINS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS
        ]
        _FAILED_LOGINS[key] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry_after = max(int(LOGIN_WINDOW_SECONDS - (now - attempts[0])), 1)
            logger.warning(f"Login throttled for {key}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )


def record_login_failure(key: str) -> None:
    now = time.time()
    with _FAILED_LOGINS_LOCK:
        attempts = [
            t for t in _FAILED_LOGINS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS
        ]
        attempts.append(now)
        _FAILED_LOGINS[key] = attempts


def clear_login_failures(key: str) -> None:
    with _FAILED_LOGINS_LOCK:
        _FAILED_LOGINS.pop(key, None)



# ─────────────────────────────────────────────
# JWT Token Management
# ─────────────────────────────────────────────

# Every token carries a unique ``jti`` so it can be revoked individually. Without
# one, "logout" was purely client-side (a localStorage delete): the access token
# stayed valid for its full lifetime and the refresh token for
# REFRESH_TOKEN_EXPIRE_DAYS, replayable by anyone who captured either.
#
# In-process denylist: a restart or an additional worker forgets it. Acceptable for
# the dev phase; production wants Redis or a `revoked_tokens` table.
_REVOKED_JTI: Dict[str, float] = {}   # jti -> unix expiry, used for pruning
_REVOKED_LOCK = threading.Lock()


def _new_jti() -> str:
    return uuid.uuid4().hex


def _prune_revoked(now: float) -> None:
    """Drop denylist entries whose tokens have expired anyway."""
    for jti, exp in list(_REVOKED_JTI.items()):
        if exp < now:
            _REVOKED_JTI.pop(jti, None)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
        "jti": _new_jti(),
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a longer-lived refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": _new_jti(),
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)



def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def revoke_token(token: str) -> Dict[str, Any]:
    """Denylist a still-valid token and return its payload.

    Raises HTTPException(401) for an already-invalid token, so logout of a garbage
    or expired token is reported rather than silently "succeeding".
    """
    payload = decode_token(token)
    jti = payload.get("jti")
    if jti:
        with _REVOKED_LOCK:
            _prune_revoked(time.time())
            _REVOKED_JTI[jti] = float(payload.get("exp") or 0)
    return payload


def is_token_revoked(payload: Dict[str, Any]) -> bool:
    """True when this token's jti has been denylisted by a logout."""
    jti = payload.get("jti")
    if not jti:
        return False
    with _REVOKED_LOCK:
        return jti in _REVOKED_JTI


# ─────────────────────────────────────────────
# FastAPI Auth Dependencies
# ─────────────────────────────────────────────

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Optional[Dict[str, Any]]:
    """Get current user from JWT token (optional - returns None if no token)."""
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
    except HTTPException:
        return None
    # An optional-auth endpoint must not accept a token that a logout has killed.
    if not payload.get("jti") or is_token_revoked(payload):
        return None
    return payload


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Dict[str, Any]:
    """Get current user from JWT token (required - raises 401 if missing/invalid)."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    # A token minted before logout support carries no jti and so could never be
    # revoked. Refuse it outright, which forces one re-login and leaves every
    # token in circulation revocable.
    if not payload.get("jti"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token predates logout support — please sign in again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if is_token_revoked(payload):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# NOTE: a `get_admin_user` dependency used to live here. It was never referenced by
# any route (api.py used its own `check_admin_role`, then later `require_roles`), so
# it was removed rather than left as a second, misleading way to require admin.


def require_roles(*roles: str):
    """Build a dependency that admits only the given roles.

    Endpoints previously stacked a `check_admin_role` dependency on top of an
    in-body `role not in ("admin", "analyst")` check. The dependency ran first,
    so analysts were rejected before the wider in-body rule could ever apply.
    Declare the accepted roles once, in one place, instead.
    """
    async def _dependency(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(roles)}",
            )
        return current_user

    return _dependency


# ─────────────────────────────────────────────
# Built-in User Store (no DB required for bootstrap)
# ─────────────────────────────────────────────

# Passwords are read from `settings` (pydantic-settings merges .env with the
# process environment). Reading os.getenv() here bypassed that layer entirely,
# so changing ADMIN_PASSWORD/ANALYST_PASSWORD/VIEWER_PASSWORD in .env had no
# effect and only the hardcoded defaults ever authenticated.
BUILTIN_USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password(settings.ADMIN_PASSWORD),
        "role": "admin",
        "full_name": "ITAP Administrator",
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": hash_password(settings.ANALYST_PASSWORD),
        "role": "analyst",
        "full_name": "SOC Analyst",
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": hash_password(settings.VIEWER_PASSWORD),
        "role": "viewer",
        "full_name": "Read-Only Viewer",
    },
}


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate user against built-in store."""
    user = BUILTIN_USERS.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user
