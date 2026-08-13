"""
TrustGuard Security Agility - Post-Quantum Transport & Hash Abstraction Shim
Wraps transport payloads in a dual classical + PQC (Post-Quantum Cryptography) hybrid container.
"""
from __future__ import annotations
import hashlib
import time
import logging
from typing import Dict, Any
from core.security.crypto_provider import CryptoEngineFactory

logger = logging.getLogger(__name__)


class PostQuantumTransportShim:
    """Hybrid classical + PQC container wrapper."""

    def __init__(self):
        self.classical_provider = CryptoEngineFactory.get_provider()

    def _compute_pqc_stub_signature(self, data: bytes) -> str:
        """
        Post-Quantum ML-DSA / Dilithium signature stub generator.
        Prepares data structure for future Quantum-Safe algorithms without breaking current wire protocol.
        """
        pqc_digest = hashlib.sha3_512(b"ML-DSA-PQC-CONTAINER-V1:" + data).hexdigest()
        return f"pqc_mldsa_{pqc_digest[:64]}"

    def pack_hybrid_container(self, payload: bytes) -> Dict[str, Any]:
        """
        Pack raw payload into hybrid dual-signature transport wrapper.
        """
        timestamp = int(time.time())
        signed_data = payload + str(timestamp).encode("utf-8")

        classical_sig = self.classical_provider.sign(signed_data)
        pqc_sig = self._compute_pqc_stub_signature(signed_data)

        return {
            "version": "2.0-PQC-HYBRID",
            "timestamp": timestamp,
            "classical_algorithm": self.classical_provider.__class__.__name__,
            "pqc_algorithm": "ML-DSA-STUB",
            "classical_signature": classical_sig,
            "pqc_signature": pqc_sig,
            "payload_b64": payload.decode("latin1"),
        }

    def unpack_and_verify(self, container: Dict[str, Any]) -> Dict[str, Any]:
        """
        Unpack and verify hybrid classical + PQC container signatures.
        """
        timestamp = container.get("timestamp", 0)
        payload = container.get("payload_b64", "").encode("latin1")
        signed_data = payload + str(timestamp).encode("utf-8")

        classical_sig = container.get("classical_signature", "")
        pqc_sig = container.get("pqc_signature", "")

        classical_valid = self.classical_provider.verify(signed_data, classical_sig)
        pqc_expected = self._compute_pqc_stub_signature(signed_data)
        pqc_valid = (pqc_sig == pqc_expected)

        is_trusted = classical_valid and pqc_valid

        return {
            "is_trusted": is_trusted,
            "classical_valid": classical_valid,
            "pqc_valid": pqc_valid,
            "payload": payload,
            "verification_details": f"Classical: {classical_valid}, PQC: {pqc_valid}",
        }
