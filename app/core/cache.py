import time
from typing import Any, Dict

# Simple in-memory LRU cache with TTL
_cache: Dict[str, tuple[float, Any]] = {}
TTL_SECONDS = 3600  # 1 hour

def get_cached_result(url: str) -> Any:
    if url in _cache:
        timestamp, result = _cache[url]
        if time.time() - timestamp < TTL_SECONDS:
            return result
        else:
            del _cache[url]
    return None

def set_cached_result(url: str, result: Any):
    # To prevent unbounded growth, clear if it gets too large
    if len(_cache) > 10000:
        _cache.clear()
    _cache[url] = (time.time(), result)
