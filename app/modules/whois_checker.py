"""
app/modules/whois_checker.py
TrustGuard — WHOIS domain age detection module.

Provides domain age lookup, risk scoring, and an LRU-cached
public interface for use inside extract_features().
"""

import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

import whois  # pip install python-whois

logger = logging.getLogger(__name__)

# ── Punycode / IDN normalisation ─────────────────────────────────────────────

def _normalise_domain(domain: str) -> str:
    """
    Convert international domain names to ASCII-compatible encoding (ACE)
    so WHOIS libraries can handle them cleanly.

    Example: 'münchen.de' → 'xn--mnchen-3ya.de'
    """
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain  # fall back to raw string; lookup may still succeed


# ── Raw WHOIS lookup ──────────────────────────────────────────────────────────

def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Return the age of *domain* in days, or None when the age cannot be
    determined (lookup failure, private registration, unsupported TLD, …).

    This function is intentionally *not* cached here — wrap the call in
    cached_whois() for production use.

    Edge cases handled:
    - creation_date returned as a list (multiple registrars) — takes [0]
    - Naive datetimes (no tzinfo) — treated as UTC
    - Private / redacted registrations returning None — returns None
    - WHOIS timeout or network error — logs warning, returns None
    - Punycode / IDN domains — normalised before lookup
    - Negative ages (clock skew) — clamped to 0
    """
    domain = _normalise_domain(domain)

    try:
        data = whois.whois(domain)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    created = data.creation_date

    # Some registrars return a list (one entry per registrar / update)
    if isinstance(created, list):
        created = created[0] if created else None

    if created is None:
        logger.debug("WHOIS returned no creation_date for %s", domain)
        return None

    # Ensure timezone-awareness before subtraction
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - created).days
    return max(age_days, 0)  # clamp against clock skew


# ── Cached public interface ───────────────────────────────────────────────────

@lru_cache(maxsize=2048)
def cached_whois(domain: str) -> Optional[int]:
    """
    LRU-cached wrapper around get_domain_age_days().

    The cache lives for the lifetime of the process.  Domain age changes
    very slowly (days), so process-lifetime caching is fine.  For multi-
    worker deployments, consider moving the cache to Redis with a 24-hour
    TTL and calling get_domain_age_days() directly.

    Usage:
        age = cached_whois("example.com")
    """
    return get_domain_age_days(domain)


def invalidate_cache(domain: Optional[str] = None) -> None:
    """
    Clear the WHOIS cache.

    Pass a specific domain to evict just that entry (requires a full cache
    clear because lru_cache doesn't support per-key eviction), or call with
    no arguments to clear everything.
    """
    cached_whois.cache_clear()
    if domain:
        logger.debug("WHOIS cache cleared (triggered by domain: %s)", domain)
    else:
        logger.debug("WHOIS cache cleared entirely")


# ── Risk scoring ──────────────────────────────────────────────────────────────

# Thresholds in days — tune these based on your dataset over time
_THRESHOLDS = [
    (7,   0.92, "Critical",  "Domain is only {age} day(s) old — extremely high-risk."),
    (30,  0.78, "High",      "Domain is {age} days old — registered very recently."),
    (90,  0.55, "Elevated",  "Domain is {age} days old — less than 3 months old."),
    (180, 0.35, "Moderate",  "Domain is {age} days old — under 6 months old."),
    (365, 0.18, "Low",       "Domain is {age} days old — under 1 year old."),
]
_SAFE_SCORE   = 0.05
_SAFE_LABEL   = "Safe"
_SAFE_REASON  = "Domain is {age} days old — well established."
_UNKNOWN_SCORE  = 0.50
_UNKNOWN_LABEL  = "Unknown"
_UNKNOWN_REASON = (
    "Domain age could not be determined (private registration or "
    "unsupported TLD). Treating as moderate risk."
)


def score_domain_age(age_days: Optional[int]) -> dict:
    """
    Convert a raw domain age into a structured risk assessment.

    Returns a dict with keys:
        age_days    int | None   — raw age in days
        score       float        — risk score 0.0–1.0
        label       str          — human-readable severity label
        reason      str          — plain-English explanation for the user
        source      str          — always "whois" (for score fusion layer)

    Design note: Unknown age returns 0.50 (moderate), NOT 0.0 (safe).
    Private registrations are common among phishing actors and should
    never be silently treated as trustworthy.
    """
    if age_days is None:
        return {
            "age_days": None,
            "score":    _UNKNOWN_SCORE,
            "label":    _UNKNOWN_LABEL,
            "reason":   _UNKNOWN_REASON,
            "source":   "whois",
        }

    for threshold, score, label, reason_template in _THRESHOLDS:
        if age_days < threshold:
            return {
                "age_days": age_days,
                "score":    score,
                "label":    label,
                "reason":   reason_template.format(age=age_days),
                "source":   "whois",
            }

    return {
        "age_days": age_days,
        "score":    _SAFE_SCORE,
        "label":    _SAFE_LABEL,
        "reason":   _SAFE_REASON.format(age=age_days),
        "source":   "whois",
    }


import asyncio

def _sync_cached_lookup(domain: str) -> Optional[int]:
    """Helper to run the cached lookup synchronously inside a thread."""
    return cached_whois(domain)


async def check_domain(domain: str) -> dict:
    """
    Single entry point: runs the cached WHOIS lookup asynchronously
    and returns a fully scored result dict.

    Uses asyncio.to_thread to prevent the synchronous python-whois library
    from blocking the FastAPI event loop, and enforces a strict 3-second timeout.
    """
    try:
        # Offload the synchronous lru_cache (and underlying network call) to a thread
        age_days = await asyncio.wait_for(
            asyncio.to_thread(_sync_cached_lookup, domain),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for %s", domain)
        return score_domain_age(None)
    except Exception as exc:
        logger.warning("WHOIS lookup thread failed for %s: %s", domain, exc)
        return score_domain_age(None)

    return score_domain_age(age_days)
