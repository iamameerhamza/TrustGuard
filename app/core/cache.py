import os
import json
import time
import hashlib
import asyncio
import logging
from typing import Any, Optional, Callable, Awaitable
from prometheus_client import Gauge

import redis.asyncio as redis
import diskcache

logger = logging.getLogger(__name__)

CACHE_BACKEND = Gauge("trustguard_cache_backend_active", "Indicates the active cache backend (1=active)", ["backend"])

# Cache settings
TTL_SECONDS = 86400  # 24 hours full expiry
STALE_SECONDS = 3600 # 1 hour until considered stale (triggers background refresh)

redis_client: Optional[redis.Redis] = None
disk_cache: Optional[diskcache.Cache] = None

def get_normalized_url_hash(url: str) -> str:
    """Hash the URL with SHA-256 to ensure consistent cache keys regardless of URL structure."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

async def init_cache():
    global redis_client, disk_cache
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    try:
        # Try to connect to Redis
        client = redis.from_url(redis_url, socket_connect_timeout=1.0)
        await client.ping()
        redis_client = client
        CACHE_BACKEND.labels(backend="redis").set(1)
        CACHE_BACKEND.labels(backend="diskcache").set(0)
        logger.info(f"Connected to Redis cache at {redis_url}")
    except Exception as e:
        logger.warning(f"Redis unavailable ({e}), falling back to diskcache")
        redis_client = None
        disk_cache = diskcache.Cache(os.getenv("DISKCACHE_DIR", "data/cache"))
        CACHE_BACKEND.labels(backend="redis").set(0)
        CACHE_BACKEND.labels(backend="diskcache").set(1)

async def _get_raw(key: str) -> Optional[str]:
    if redis_client:
        val = await redis_client.get(key)
        return val.decode("utf-8") if val else None
    elif disk_cache:
        # diskcache is blocking, run in thread pool just to be safe if heavily concurrent
        return await asyncio.to_thread(disk_cache.get, key)
    return None

async def _set_raw(key: str, value: str, ttl: int):
    if redis_client:
        await redis_client.setex(key, ttl, value)
    elif disk_cache:
        await asyncio.to_thread(disk_cache.set, key, value, expire=ttl)

async def get_cached_result(url: str, revalidate_func: Optional[Callable[[], Awaitable[Any]]] = None) -> Any:
    key = f"scan_result:{get_normalized_url_hash(url)}"
    raw_data = await _get_raw(key)
    
    if not raw_data:
        return None
        
    try:
        data = json.loads(raw_data)
        fetched_at = data.get("_fetched_at", 0)
        result = data.get("result")
        
        # Stale-while-revalidate
        if revalidate_func and (time.time() - fetched_at > STALE_SECONDS):
            logger.info(f"Cache entry for {url} is stale. Spawning background revalidation.")
            asyncio.create_task(_revalidate_task(url, key, revalidate_func))
            
        return result
    except Exception as e:
        logger.error(f"Failed to parse cache payload for {url}: {e}")
        return None

async def set_cached_result(url: str, result: Any):
    key = f"scan_result:{get_normalized_url_hash(url)}"
    
    # Store with _fetched_at timestamp for stale-while-revalidate logic
    payload = {
        "_fetched_at": time.time(),
        "result": result
    }
    
    # We must serialize the response object to JSON (usually it's a Pydantic model)
    try:
        # If it's a pydantic model, it has .model_dump()
        if hasattr(result, "model_dump"):
            payload["result"] = result.model_dump()
        elif hasattr(result, "dict"):
            payload["result"] = result.dict()
            
        raw_data = json.dumps(payload)
        await _set_raw(key, raw_data, TTL_SECONDS)
    except Exception as e:
        logger.error(f"Failed to serialize cache payload for {url}: {e}")

async def _revalidate_task(url: str, key: str, revalidate_func: Callable[[], Awaitable[Any]]):
    """Background task to fetch fresh data and update cache."""
    try:
        fresh_result = await revalidate_func()
        if fresh_result:
            await set_cached_result(url, fresh_result)
            logger.info(f"Successfully revalidated cache for {url}")
    except Exception as e:
        logger.error(f"Failed to revalidate cache for {url}: {e}")

class AsyncMemoryRedis:
    """Duck-typed async Redis wrapper backed by diskcache for VT compatibility."""
    def __init__(self, namespace: str = "vt"):
        self.namespace = namespace
        if not disk_cache and not redis_client:
            # We initialize here if not called by lifespan
            # We can just fall back to a local disk cache for VT
            self.local_cache = diskcache.Cache("data/vt_cache")
        else:
            self.local_cache = None

    def _key(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    async def get(self, key: str) -> Any:
        namespaced_key = self._key(key)
        if redis_client:
            val = await redis_client.get(namespaced_key)
            return val.decode("utf-8") if val else None
        elif disk_cache:
            return await asyncio.to_thread(disk_cache.get, namespaced_key)
        else:
            return await asyncio.to_thread(self.local_cache.get, namespaced_key)

    async def setex(self, key: str, ttl: int, value: Any) -> None:
        namespaced_key = self._key(key)
        if redis_client:
            await redis_client.setex(namespaced_key, ttl, str(value))
        elif disk_cache:
            await asyncio.to_thread(disk_cache.set, namespaced_key, str(value), expire=ttl)
        else:
            await asyncio.to_thread(self.local_cache.set, namespaced_key, str(value), expire=ttl)
