"""
TrustGuard Security - Cryptographically Signed Threat Feed Verifier
Verifies origin, payload integrity, and timestamp validity of downloaded threat intelligence updates.
"""
from __future__ import annotations
import hmac
import hashlib
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SignedFeedVerifier:
    """Verifies cryptographic signatures on threat feed updates."""

    def __init__(self, secret_key: str = "TG_TRUSTED_FEED_SIGNING_KEY_2026"):
        self.secret_key = secret_key.encode("utf-8")

    def compute_signature(self, payload_bytes: bytes, timestamp: int) -> str:
        """Compute HMAC-SHA256 signature for feed payload and timestamp."""
        msg = payload_bytes + str(timestamp).encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def verify_feed_package(self, payload_bytes: bytes, signature_hex: str, timestamp: int, max_age_seconds: int = 86400) -> Dict[str, Any]:
        """
        Verify threat feed package integrity, signature, and freshness.
        """
        now = int(time.time())

        # 1. Anti-Replay Timestamp Check
        if abs(now - timestamp) > max_age_seconds:
            return {
                "is_valid": False,
                "reason": f"Feed package expired or timestamp invalid (age: {now - timestamp}s)",
            }

        # 2. Signature verification
        expected_sig = self.compute_signature(payload_bytes, timestamp)
        if not hmac.compare_digest(expected_sig.lower(), signature_hex.lower()):
            return {
                "is_valid": False,
                "reason": "Cryptographic signature mismatch - feed payload corrupted or forged",
            }

        return {
            "is_valid": True,
            "reason": "Feed signature and timestamp verified successfully",
            "timestamp": timestamp,
        }
