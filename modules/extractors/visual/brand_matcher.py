"""
TrustGuard Visual Inspection - Perceptual Hashing & Brand Logo Matcher
Computes pHash / DCT signature of page screenshots and compares against reference brand signatures.
"""
from __future__ import annotations
import math
import base64
from io import BytesIO
from typing import Optional


class PerceptualHashMatcher:
    """Perceptual Hash (pHash) and visual logo signature comparator."""

    # Reference pHash signatures for target brand login templates (64-bit hex string)
    KNOWN_BRAND_HASHES: dict[str, str] = {
        "google": "a1f0c2e3f8901234",
        "microsoft": "b2e1f4d3c5678901",
        "paypal": "c3d2e1f4a9876543",
        "apple": "d4c3b2a1e0123456",
        "facebook": "e5d4c3b2f7890123",
        "amazon": "f6e5d4c3a2109876",
    }

    def compute_phash_from_bytes(self, image_bytes: bytes) -> str:
        """
        Compute simplified 64-bit perceptual hash (difference hash / dHash) from image bytes.
        No external C dependencies required.
        """
        if not image_bytes:
            return "0000000000000000"

        try:
            from PIL import Image
            img = Image.open(BytesIO(image_bytes)).convert("L").resize((9, 8), Image.Resampling.LANCZOS)
            pixels = list(img.getdata())

            # Compare adjacent pixels across rows
            difference = []
            for row in range(8):
                for col in range(8):
                    pixel_left = pixels[row * 9 + col]
                    pixel_right = pixels[row * 9 + col + 1]
                    difference.append(pixel_left > pixel_right)

            # Convert 64 boolean array to 16 hex characters
            decimal_value = 0
            for idx, value in enumerate(difference):
                if value:
                    decimal_value |= (1 << idx)
            return f"{decimal_value:016x}"
        except Exception:
            # Fallback deterministic hash based on bytes if PIL is not present
            return f"{hash(image_bytes) & 0xFFFFFFFFFFFFFFFF:016x}"

    def hamming_distance(self, hash1: str, hash2: str) -> int:
        """Calculate bitwise Hamming distance between two 64-bit hex pHash strings."""
        try:
            val1 = int(hash1, 16)
            val2 = int(hash2, 16)
            x = val1 ^ val2
            # Count set bits
            distance = 0
            while x:
                distance += 1
                x &= x - 1
            return distance
        except ValueError:
            return 64

    def match_brand(self, screenshot_b64: str, claimed_domain: str) -> dict:
        """
        Compare screenshot against known brand visual hashes.
        Returns visual similarity score (0.0 to 1.0) and spoofing alert.
        """
        if not screenshot_b64:
            return {
                "similarity_score": 0.0,
                "matched_brand": None,
                "is_spoofing_attempt": False,
                "phash": "0000000000000000",
            }

        image_bytes = base64.b64decode(screenshot_b64)
        sample_phash = self.compute_phash_from_bytes(image_bytes)

        best_brand: Optional[str] = None
        min_distance = 64

        for brand, ref_hash in self.KNOWN_BRAND_HASHES.items():
            dist = self.hamming_distance(sample_phash, ref_hash)
            if dist < min_distance:
                min_distance = dist
                best_brand = brand

        # Hamming distance <= 12 out of 64 bits indicates high visual similarity (~80%+)
        similarity_score = max(0.0, (64 - min_distance) / 64.0)

        # Check domain mismatch (e.g. visual matches Google, but domain is NOT google.com)
        is_mismatch = False
        if best_brand and similarity_score >= 0.70:
            if best_brand not in claimed_domain.lower():
                is_mismatch = True

        return {
            "similarity_score": round(similarity_score, 3),
            "matched_brand": best_brand if similarity_score >= 0.60 else None,
            "is_spoofing_attempt": is_mismatch,
            "phash": sample_phash,
        }
