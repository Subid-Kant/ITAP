"""
ITAP — Redis Cache Module
Centralised Redis client with graceful fallback (no crash if Redis is unavailable).
"""
import logging
from typing import Optional, Any
import json

logger = logging.getLogger("itap.cache")

# Try to import redis; fall back to None if not installed
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    REDIS_AVAILABLE = False

# Module-level client (initialized on first use)
_redis_client: Optional[Any] = None
_cache_enabled: bool = False


async def get_redis_client():
    """Get or create the Redis async client."""
    global _redis_client, _cache_enabled
    
    if not REDIS_AVAILABLE:
        return None
    
    if _redis_client is not None:
        return _redis_client
    
    try:
        from app.core.config import settings
        redis_url = getattr(settings, 'REDIS_URL', 'redis://localhost:6379')
        client = aioredis.from_url(redis_url, decode_responses=True)
        await client.ping()  # Test connection
        _redis_client = client
        _cache_enabled = True
        logger.info(f"✅ Redis cache connected: {redis_url}")
        return client
    except Exception as e:
        logger.warning(f"⚠️  Redis not available (cache disabled): {e}")
        _cache_enabled = False
        return None


async def cache_get(key: str) -> Optional[dict]:
    """Get a cached value by key. Returns None if not found or Redis unavailable."""
    client = await get_redis_client()
    if not client:
        return None
    try:
        value = await client.get(key)
        if value:
            logger.debug(f"Cache HIT: {key}")
            return json.loads(value)
        logger.debug(f"Cache MISS: {key}")
        return None
    except Exception as e:
        logger.warning(f"Cache get failed for {key}: {e}")
        return None


async def cache_set(key: str, value: dict, ttl_seconds: int = 86400) -> bool:
    """Store a value in Redis with TTL. Returns True on success."""
    client = await get_redis_client()
    if not client:
        return False
    try:
        serialized = json.dumps(value, default=str)
        await client.setex(key, ttl_seconds, serialized)
        logger.debug(f"Cache SET: {key} (TTL={ttl_seconds}s)")
        return True
    except Exception as e:
        logger.warning(f"Cache set failed for {key}: {e}")
        return False


async def cache_delete(key: str) -> bool:
    """Delete a cache entry."""
    client = await get_redis_client()
    if not client:
        return False
    try:
        await client.delete(key)
        return True
    except Exception as e:
        logger.warning(f"Cache delete failed for {key}: {e}")
        return False


def make_scan_cache_key(domain: str, ip: str = "") -> str:
    """Generate a consistent cache key for OSINT scan results."""
    return f"itap:osint:scan:{domain}:{ip}"


async def health_check() -> dict:
    """Check Redis connectivity and return status."""
    client = await get_redis_client()
    if not client:
        return {"redis": "unavailable", "cache_enabled": False}
    try:
        await client.ping()
        info = await client.info("server")
        return {
            "redis": "connected",
            "cache_enabled": True,
            "version": info.get("redis_version", "unknown"),
        }
    except Exception as e:
        return {"redis": "error", "cache_enabled": False, "error": str(e)}
