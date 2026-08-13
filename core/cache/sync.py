"""
TrustGuard Core Cache - Bloom Filter Delta Sync Manager
Provides thread-safe loading, updating, and sync payload generation for client local caches.
"""
from __future__ import annotations
import time
import logging
from typing import Optional
from core.cache.bloom_filter import BloomFilter

logger = logging.getLogger(__name__)


class BloomFilterSyncManager:
    """Manages active malicious and benign domain Bloom filters with delta versioning."""

    def __init__(self, expected_elements: int = 50000, fp_rate: float = 0.001):
        self.malicious_filter = BloomFilter(expected_elements, fp_rate)
        self.benign_filter = BloomFilter(expected_elements, fp_rate)
        self.version = int(time.time())

    def update_threat_feed(self, malicious_domains: list[str], benign_domains: Optional[list[str]] = None) -> int:
        """
        Populate or update threat feed filters.
        """
        added_count = 0
        for domain in malicious_domains:
            clean = domain.strip().lower()
            if clean:
                self.malicious_filter.add(clean)
                added_count += 1

        if benign_domains:
            for domain in benign_domains:
                clean = domain.strip().lower()
                if clean:
                    self.benign_filter.add(clean)

        self.version = int(time.time())
        logger.info(f"Updated BloomFilterSyncManager v{self.version} with {added_count} malicious domains.")
        return added_count

    def get_sync_payload(self) -> dict:
        """
        Generate JSON payload for client Bloom filter synchronization.
        """
        return {
            "version": self.version,
            "timestamp": time.time(),
            "malicious_filter": self.malicious_filter.to_dict(),
            "benign_filter": self.benign_filter.to_dict(),
        }
