"""
ITAP — Security & Authentication Core
JWT token management, password hashing, and FastAPI auth dependencies.
"""
import os
import logging
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
    """Verify a password against its hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ─────────────────────────────────────────────
# JWT Token Management
# ─────────────────────────────────────────────

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a longer-lived refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})
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
        return payload
    except HTTPException:
        return None


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
    return payload


async def get_admin_user(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Require admin role."""
    if current_user.get("role") not in ("admin",):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# ─────────────────────────────────────────────
# Built-in User Store (no DB required for bootstrap)
# ─────────────────────────────────────────────

BUILTIN_USERS = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password(os.getenv("ADMIN_PASSWORD", "ITAP@Admin2025!")),
        "role": "admin",
        "full_name": "ITAP Administrator",
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": hash_password(os.getenv("ANALYST_PASSWORD", "ITAP@Analyst2025!")),
        "role": "analyst",
        "full_name": "SOC Analyst",
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": hash_password(os.getenv("VIEWER_PASSWORD", "ITAP@Viewer2025!")),
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
