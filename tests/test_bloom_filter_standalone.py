"""
Standalone unit tests for Bloom Filter core functionality.
"""
import unittest
from core.cache.bloom_filter import BloomFilter
from core.cache.sync import BloomFilterSyncManager


class TestBloomFilterStandalone(unittest.TestCase):
    def test_bloom_filter_operations(self):
        bf = BloomFilter(expected_elements=1000, false_positive_rate=0.001)
        bf.add("phishing-example.com")
        bf.add("malicious-login.xyz")

        self.assertTrue("phishing-example.com" in bf)
        self.assertTrue("malicious-login.xyz" in bf)
        self.assertFalse("google.com" in bf)

    def test_bloom_filter_serialization(self):
        bf = BloomFilter(expected_elements=500, false_positive_rate=0.01)
        bf.add("test-domain.org")

        serialized = bf.to_dict()
        reconstructed = BloomFilter.from_dict(serialized)

        self.assertTrue("test-domain.org" in reconstructed)
        self.assertFalse("safe-domain.com" in reconstructed)

    def test_sync_manager(self):
        sync_mgr = BloomFilterSyncManager(expected_elements=500)
        sync_mgr.update_threat_feed(
            malicious_domains=["bad-link.com"],
            benign_domains=["wikipedia.org"]
        )
        self.assertTrue("bad-link.com" in sync_mgr.malicious_filter)
        self.assertTrue("wikipedia.org" in sync_mgr.benign_filter)


if __name__ == "__main__":
    unittest.main()
