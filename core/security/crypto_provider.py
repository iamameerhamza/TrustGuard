"""
TrustGuard Security Agility - Pluggable Cryptographic Signature Engine
Abstracts cryptographic algorithms behind a unified interface supporting runtime algorithm swapping.
"""
from __future__ import annotations
import os
import hmac
import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any

logger = logging.getLogger(__name__)


class CryptoProvider(ABC):
    """Abstract Cryptographic Provider Interface."""
    
    @abstractmethod
    def sign(self, data: bytes) -> str:
        """Generate signature for binary payload."""
        pass

    @abstractmethod
    def verify(self, data: bytes, signature_hex: str) -> bool:
        """Verify signature for binary payload."""
        pass


class HmacSha256Provider(CryptoProvider):
    """HMAC-SHA256 Signature Provider."""

    def __init__(self, key: str = "TG_CRYPTO_PROVIDER_DEFAULT_KEY"):
        self.key = key.encode("utf-8")

    def sign(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected.lower(), signature_hex.lower())


class Ed25519StubProvider(CryptoProvider):
    """Ed25519 High-Speed Signature Provider Stub."""

    def __init__(self, key: str = "TG_ED25519_KEY_STUB"):
        self.key = key.encode("utf-8")

    def sign(self, data: bytes) -> str:
        # Ed25519 domain separation prefix hash
        return hashlib.blake2b(b"Ed25519:" + self.key + data, digest_size=32).hexdigest()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected.lower(), signature_hex.lower())


class CryptoEngineFactory:
    """Factory selecting crypto provider based on env var `CRYPTO_ALGORITHM`."""

    @staticmethod
    def get_provider() -> CryptoProvider:
        algo = os.getenv("CRYPTO_ALGORITHM", "HMAC_SHA256").upper()

        if algo in ("ED25519", "ED25519_STUB"):
            logger.info("Using Ed25519 Cryptographic Provider")
            return Ed25519StubProvider()

        logger.info("Using HMAC-SHA256 Cryptographic Provider")
        return HmacSha256Provider()
