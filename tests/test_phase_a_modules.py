"""
Unit tests for Phase A Micro-Modules (MM-1.1, MM-1.2, MM-1.3)
"""
import unittest
import hashlib
from core.cache.bloom_filter import BloomFilter
from core.cache.sync import BloomFilterSyncManager
from app.api.v1.anonymized_scan import KNOWN_THREAT_HASHES


class TestPhaseAModules(unittest.TestCase):
    def test_bloom_filter_basic_operations(self):
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

    def test_bloom_filter_sync_manager(self):
        sync_mgr = BloomFilterSyncManager(expected_elements=500)
        added = sync_mgr.update_threat_feed(
            malicious_domains=["bad-link.com", "fake-bank.net"],
            benign_domains=["wikipedia.org"]
        )
        self.assertEqual(added, 2)
        self.assertTrue("bad-link.com" in sync_mgr.malicious_filter)
        self.assertTrue("wikipedia.org" in sync_mgr.benign_filter)

        payload = sync_mgr.get_sync_payload()
        self.assertIn("malicious_filter", payload)
        self.assertIn("benign_filter", payload)

    def test_k_anonymity_known_hashes(self):
        target = "phishing-example.com"
        target_hash = hashlib.sha256(target.encode()).hexdigest()
        prefix = target_hash[:5]

        self.assertIn(target_hash, KNOWN_THREAT_HASHES)
        self.assertTrue(target_hash.startswith(prefix))


if __name__ == "__main__":
    unittest.main()
