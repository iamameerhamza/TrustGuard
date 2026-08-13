"""
TrustGuard Core Cache - Double-Hashing Bloom Filter
Provides high-speed, space-efficient set membership testing with low false-positive rate (< 0.1%).
"""
from __future__ import annotations
import math
import hashlib
from typing import Any


class BloomFilter:
    """
    Space-efficient probabilistic data structure using Kirsch-Mitzenmacher 
    double-hashing scheme: h_i(x) = (hash1(x) + i * hash2(x)) % m
    """

    def __init__(self, expected_elements: int = 10000, false_positive_rate: float = 0.001):
        """
        Initialize Bloom Filter parameters.
        m = - (n * ln(p)) / (ln(2)^2)
        k = (m / n) * ln(2)
        """
        self.expected_elements = max(1, expected_elements)
        self.false_positive_rate = min(max(false_positive_rate, 0.00001), 0.1)

        # Calculate bit array size (m) and number of hash functions (k)
        self.size = int(math.ceil(
            -1 * (self.expected_elements * math.log(self.false_positive_rate)) / (math.log(2) ** 2)
        ))
        self.hash_count = max(1, int(round((self.size / self.expected_elements) * math.log(2))))
        
        # Bit array initialized to zeros
        self.bit_array = bytearray((self.size + 7) // 8)
        self.element_count = 0

    def _get_hashes(self, item: str) -> tuple[int, int]:
        """
        Generate two 64-bit integer hashes using SHA-256 for double hashing.
        """
        digest = hashlib.sha256(item.encode('utf-8')).digest()
        hash1 = int.from_bytes(digest[:8], byteorder='big')
        hash2 = int.from_bytes(digest[8:16], byteorder='big')
        return hash1, hash2

    def _get_bit_indices(self, item: str) -> list[int]:
        """
        Compute k bit indices using Kirsch-Mitzenmacher double hashing.
        """
        hash1, hash2 = self._get_hashes(item)
        return [
            (hash1 + i * hash2) % self.size 
            for i in range(self.hash_count)
        ]

    def add(self, item: str) -> None:
        """
        Add an item (domain or URL) to the Bloom filter.
        """
        if not item:
            return
        for index in self._get_bit_indices(item):
            byte_idx = index // 8
            bit_idx = index % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self.element_count += 1

    def __contains__(self, item: str) -> bool:
        """
        Check if item is possibly in the Bloom filter.
        Returns True if item might be present, False if definitely NOT present.
        """
        if not item:
            return False
        for index in self._get_bit_indices(item):
            byte_idx = index // 8
            bit_idx = index % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """
        Export filter parameters and hex-encoded bit array for JSON transfer.
        """
        return {
            "size": self.size,
            "hash_count": self.hash_count,
            "expected_elements": self.expected_elements,
            "false_positive_rate": self.false_positive_rate,
            "element_count": self.element_count,
            "bits_hex": self.bit_array.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BloomFilter:
        """
        Reconstruct BloomFilter from exported dict payload.
        """
        bf = cls(
            expected_elements=data.get("expected_elements", 10000),
            false_positive_rate=data.get("false_positive_rate", 0.001)
        )
        bf.size = data["size"]
        bf.hash_count = data["hash_count"]
        bf.element_count = data.get("element_count", 0)
        bf.bit_array = bytearray.fromhex(data["bits_hex"])
        return bf
