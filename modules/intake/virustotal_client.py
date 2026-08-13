from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse, urlunparse

import aiohttp

logger = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3/urls/"
VT_ENGINE_FLOOR = 18
DEFAULT_TIMEOUT_SECONDS = 7.0
DEFAULT_MAX_RETRIES = 4
DEFAULT_SOFT_TTL_SECONDS = 1800
DEFAULT_HARD_TTL_SECONDS = 21600
DEFAULT_BACKOFF_SECONDS = 0.5


from enum import Enum

class VTSignalState(str, Enum):
    SCORED = "scored"
    NOT_YET_SCANNED = "not_yet_scanned"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    ERROR = "error"

@dataclass(slots=True)
class VTSignal:
    url: str
    state: VTSignalState
    score: Optional[float] = None
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    engines_total: int = 0
    engines_scored: int = 0
    engines: Optional[Dict[str, bool]] = None
    cache_key: Optional[str] = None
    fetched_at: Optional[float] = None
    error: Optional[str] = None
    raw_stats: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VTSignal":
        raw_stats = data.get("raw_stats") or data.get("stats") or {}
        if not isinstance(raw_stats, dict):
            raw_stats = {}

        engines = data.get("engines")
        if not isinstance(engines, dict):
            engines = None

        return cls(
            url=str(data.get("url", "")),
            state=str(data.get("state", "error")),
            score=_as_optional_float(data.get("score")),
            malicious=int(data.get("malicious", 0) or 0),
            suspicious=int(data.get("suspicious", 0) or 0),
            harmless=int(data.get("harmless", 0) or 0),
            undetected=int(data.get("undetected", 0) or 0),
            timeout=int(data.get("timeout", 0) or 0),
            engines_total=int(data.get("engines_total", 0) or 0),
            engines_scored=int(data.get("engines_scored", 0) or 0),
            engines=engines,
            cache_key=data.get("cache_key"),
            fetched_at=_as_optional_float(data.get("fetched_at")),
            error=data.get("error"),
            raw_stats={key: int(value) for key, value in raw_stats.items() if isinstance(value, (int, float))},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "state": self.state,
            "score": self.score,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "timeout": self.timeout,
            "engines_total": self.engines_total,
            "engines_scored": self.engines_scored,
            "engines": self.engines,
            "cache_key": self.cache_key,
            "fetched_at": self.fetched_at,
            "error": self.error,
            "raw_stats": self.raw_stats,
        }


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        redis_client: Any,
        session: Optional[aiohttp.ClientSession] = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        soft_ttl_seconds: int = DEFAULT_SOFT_TTL_SECONDS,
        hard_ttl_seconds: int = DEFAULT_HARD_TTL_SECONDS,
        engine_floor: int = VT_ENGINE_FLOOR,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    ):
        self.api_key = api_key
        self.redis = redis_client
        self.session = session
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.soft_ttl_seconds = soft_ttl_seconds
        self.hard_ttl_seconds = hard_ttl_seconds
        self.engine_floor = engine_floor
        self.backoff_seconds = backoff_seconds
        self._owns_session = session is None
        self._refresh_tasks: set[asyncio.Task[Any]] = set()

    async def close(self) -> None:
        if self.session and not self.session.closed and self._owns_session:
            await self.session.close()

    async def scan_url(self, url: str) -> VTSignal:
        canonical_url = self._canonicalize_url(url)
        cache_key = self._cache_key(canonical_url)

        cached_signal = await self._load_cached_signal(cache_key)
        if cached_signal is not None:
            if self._is_fresh(cached_signal):
                return cached_signal
            if self._within_stale_window(cached_signal):
                self._schedule_refresh(canonical_url, cache_key)
                return cached_signal

        signal = await self._fetch_signal(canonical_url, cache_key)
        await self._store_signal(signal)
        return signal

    async def _fetch_signal(self, canonical_url: str, cache_key: str) -> VTSignal:
        session = await self._get_session()
        url_id = base64.urlsafe_b64encode(canonical_url.encode("utf-8")).decode("ascii").rstrip("=")
        request_url = f"{VT_API_URL}{url_id}"
        headers = {"x-apikey": self.api_key}

        last_error: Optional[str] = None
        for attempt in range(self.max_retries + 1):
            try:
                async with session.get(
                    request_url,
                    headers=headers,
                    timeout=self.timeout_seconds,
                ) as response:
                    if response.status == 200:
                        payload = await response.json()
                        return self._build_signal(canonical_url, cache_key, payload)

                    if response.status == 404:
                        return VTSignal(
                            url=canonical_url,
                            state=VTSignalState.NOT_YET_SCANNED,
                            score=0.0,
                            cache_key=cache_key,
                        )

                    if response.status == 429 or 500 <= response.status < 600:
                        last_error = f"HTTP {response.status}"
                        if attempt < self.max_retries:
                            await asyncio.sleep(self._backoff_delay(attempt))
                            continue
                        break

                    body_text = await self._safe_text(response)
                    return VTSignal(
                        url=canonical_url,
                        state=VTSignalState.ERROR,
                        score=0.0,
                        cache_key=cache_key,
                        error=f"Unexpected VirusTotal status {response.status}: {body_text}".strip(),
                    )
            except asyncio.TimeoutError:
                last_error = "timeout"
                if attempt < self.max_retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                break
            except aiohttp.ClientError as exc:
                last_error = str(exc)
                if attempt < self.max_retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                break
            except Exception as exc:
                return VTSignal(
                    url=canonical_url,
                    state=VTSignalState.ERROR,
                    score=0.0,
                    cache_key=cache_key,
                    error=str(exc),
                )

        return VTSignal(
            url=canonical_url,
            state=VTSignalState.ERROR,
            score=0.0,
            cache_key=cache_key,
            error=last_error or "VirusTotal request failed",
        )

    def _build_signal(self, canonical_url: str, cache_key: str, payload: Mapping[str, Any]) -> VTSignal:
        stats = self._extract_stats(payload)
        if not stats:
            return VTSignal(
                url=canonical_url,
                state=VTSignalState.ERROR,
                score=0.0,
                cache_key=cache_key,
                error="VirusTotal response did not contain analysis stats",
            )

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        timeout = int(stats.get("timeout", 0))
        engines_total = sum(max(int(value), 0) for value in stats.values())
        engines_scored = max(engines_total - undetected - timeout, 0)

        if engines_total == 0:
            return VTSignal(
                url=canonical_url,
                state=VTSignalState.NOT_YET_SCANNED,
                score=0.0,
                cache_key=cache_key,
                raw_stats=dict(stats),
            )

        if engines_total < self.engine_floor:
            return VTSignal(
                url=canonical_url,
                state=VTSignalState.INSUFFICIENT_COVERAGE,
                score=self._score_from_stats(malicious, suspicious, engines_scored),
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                timeout=timeout,
                engines_total=engines_total,
                engines_scored=engines_scored,
                cache_key=cache_key,
                raw_stats=dict(stats),
            )

        if engines_scored <= 0:
            return VTSignal(
                url=canonical_url,
                state=VTSignalState.NOT_YET_SCANNED,
                score=0.0,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                timeout=timeout,
                engines_total=engines_total,
                engines_scored=engines_scored,
                cache_key=cache_key,
                raw_stats=dict(stats),
            )

        score = self._score_from_stats(malicious, suspicious, engines_scored)
        return VTSignal(
            url=canonical_url,
            state=VTSignalState.SCORED,
            score=score,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            timeout=timeout,
            engines_total=engines_total,
            engines_scored=engines_scored,
            cache_key=cache_key,
            raw_stats=dict(stats),
        )

    def _score_from_stats(self, malicious: int, suspicious: int, engines_scored: int) -> float:
        if engines_scored <= 0:
            return 0.0
        raw = (malicious + (0.5 * suspicious)) / engines_scored
        return round(max(0.0, min(1.0, raw)) * 100.0, 2)

    async def _load_cached_signal(self, cache_key: str) -> Optional[VTSignal]:
        cached = await self._maybe_await(self.redis.get(cache_key))
        if not cached:
            return None

        if isinstance(cached, bytes):
            cached = cached.decode("utf-8")

        try:
            payload = json.loads(cached)
        except (TypeError, json.JSONDecodeError):
            return None

        if isinstance(payload, dict) and "signal" in payload:
            signal_data = payload.get("signal", {})
        else:
            signal_data = payload

        if not isinstance(signal_data, dict):
            return None

        signal = VTSignal.from_dict(signal_data)
        if signal.cache_key is None:
            signal.cache_key = cache_key
        return signal

    async def _store_signal(self, signal: VTSignal) -> None:
        signal.fetched_at = time.time()
        if signal.cache_key is None:
            signal.cache_key = self._cache_key(signal.url)

        payload = json.dumps(
            {
                "signal": signal.to_dict(),
                "cached_at": signal.fetched_at,
                "soft_ttl_seconds": self.soft_ttl_seconds,
                "hard_ttl_seconds": self.hard_ttl_seconds,
            }
        )
        await self._maybe_await(self.redis.setex(signal.cache_key, self.hard_ttl_seconds, payload))

    def _schedule_refresh(self, canonical_url: str, cache_key: str) -> None:
        try:
            task = asyncio.create_task(self._refresh_signal(canonical_url, cache_key))
        except RuntimeError:
            return

        self._refresh_tasks.add(task)
        task.add_done_callback(self._refresh_tasks.discard)

    async def _refresh_signal(self, canonical_url: str, cache_key: str) -> None:
        signal = await self._fetch_signal(canonical_url, cache_key)
        if signal.state != "error":
            await self._store_signal(signal)

    def _is_fresh(self, signal: VTSignal) -> bool:
        if signal.fetched_at is None:
            return False
        return (time.time() - signal.fetched_at) <= self.soft_ttl_seconds

    def _within_stale_window(self, signal: VTSignal) -> bool:
        if signal.fetched_at is None:
            return False
        return (time.time() - signal.fetched_at) <= self.hard_ttl_seconds

    def _canonicalize_url(self, url: str) -> str:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower() if parsed.scheme else "https"
        if scheme not in {"http", "https"}:
            scheme = "https"

        netloc = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if not netloc:
            raise ValueError("URL must include a host")

        netloc = netloc.lower()
        hostname, port = _split_netloc(netloc)
        if port is not None and _is_default_port(scheme, port):
            port = None

        canonical_netloc = hostname if port is None else f"{hostname}:{port}"
        canonical_path = path or "/"
        canonical_path = canonical_path.rstrip("/") or "/"
        return urlunparse((scheme, canonical_netloc, canonical_path, "", parsed.query, ""))

    def _cache_key(self, canonical_url: str) -> str:
        return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()

    def _extract_stats(self, payload: Mapping[str, Any]) -> Dict[str, int]:
        data = payload.get("data", {})
        if not isinstance(data, dict):
            return {}

        attributes = data.get("attributes", {})
        if not isinstance(attributes, dict):
            return {}

        candidate_stats = attributes.get("last_analysis_stats", {})
        if not isinstance(candidate_stats, dict):
            return {}

        stats: Dict[str, int] = {}
        for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
            value = candidate_stats.get(key, 0)
            if isinstance(value, (int, float)):
                stats[key] = max(int(value), 0)
        return stats

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            self.session = aiohttp.ClientSession(timeout=timeout)
            self._owns_session = True
        return self.session

    async def _maybe_await(self, value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    async def _safe_text(self, response: Any) -> str:
        try:
            return await response.text()
        except Exception:
            return ""

    def _backoff_delay(self, attempt: int) -> float:
        return self.backoff_seconds * (2**attempt)


def _as_optional_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _split_netloc(netloc: str) -> tuple[str, Optional[int]]:
    if ":" not in netloc:
        return netloc, None

    hostname, port_text = netloc.rsplit(":", 1)
    try:
        return hostname, int(port_text)
    except ValueError:
        return netloc, None


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)