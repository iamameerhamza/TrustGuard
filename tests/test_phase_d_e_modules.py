"""
Unit tests for Phase D (MM-4.1, MM-4.2, MM-4.3) and Phase E (MM-5.1, MM-5.2) Micro-Modules
"""
import unittest
import time
from modules.federated.differential_privacy import DifferentialPrivacyCollector
from core.security.feed_verifier import SignedFeedVerifier
from modules.federated.aggregator import FederatedModelAggregator
from core.security.crypto_provider import CryptoEngineFactory, HmacSha256Provider, Ed25519StubProvider
from core.security.pqc_transport import PostQuantumTransportShim


class TestPhaseDEModules(unittest.TestCase):
    def test_differential_privacy_collector(self):
        collector = DifferentialPrivacyCollector(epsilon=1.0)
        original_features = {"entropy": 4.5, "subdomain_count": 3.0}

        payload = collector.create_privacy_preserving_payload("false_positive", original_features)

        self.assertTrue(payload["anonymized"])
        self.assertIn("entropy", payload["noised_features"])
        # Verify noise perturbed feature value
        self.assertIsInstance(payload["noised_features"]["entropy"], float)

    def test_signed_feed_verifier(self):
        verifier = SignedFeedVerifier(secret_key="TEST_KEY")
        payload = b"phishing-domain1.com,phishing-domain2.xyz"
        now = int(time.time())

        sig = verifier.compute_signature(payload, now)

        result = verifier.verify_feed_package(payload, sig, now)
        self.assertTrue(result["is_valid"])

        # Tampered payload check
        tampered_result = verifier.verify_feed_package(b"tampered_payload", sig, now)
        self.assertFalse(tampered_result["is_valid"])

    def test_federated_model_aggregator(self):
        aggregator = FederatedModelAggregator(outlier_threshold=2.0)
        client_updates = [
            {"entropy_weight": 0.5, "keyword_weight": 0.8},
            {"entropy_weight": 0.52, "keyword_weight": 0.78},
            {"entropy_weight": 0.48, "keyword_weight": 0.82},
            {"entropy_weight": 100.0, "keyword_weight": 0.81},  # Malicious outlier
        ]

        aggregated = aggregator.aggregate_updates(client_updates)

        # Verify outlier (100.0) was filtered out
        self.assertLess(aggregated["entropy_weight"], 5.0)

    def test_pluggable_crypto_provider(self):
        provider = CryptoEngineFactory.get_provider()
        data = b"trustguard-security-data"

        sig = provider.sign(data)
        self.assertTrue(provider.verify(data, sig))

    def test_pqc_hybrid_transport(self):
        shim = PostQuantumTransportShim()
        payload = b"Sample Threat Intelligence Record"

        container = shim.pack_hybrid_container(payload)
        self.assertEqual(container["version"], "2.0-PQC-HYBRID")

        verification = shim.unpack_and_verify(container)
        self.assertTrue(verification["is_trusted"])
        self.assertTrue(verification["classical_valid"])
        self.assertTrue(verification["pqc_valid"])


if __name__ == "__main__":
    unittest.main()
