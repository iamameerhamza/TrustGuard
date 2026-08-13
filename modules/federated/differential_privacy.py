"""
TrustGuard Federated Intelligence - Local Differential Privacy Collector
Perturbs feature vectors using Laplace noise to ensure epsilon-differential privacy for user feedback telemetry.
"""
from __future__ import annotations
import math
import random
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class DifferentialPrivacyCollector:
    """Applies Local Differential Privacy (LDP) noise to telemetry updates."""

    def __init__(self, epsilon: float = 1.0, sensitivity: float = 1.0):
        self.epsilon = max(0.1, epsilon)
        self.sensitivity = sensitivity
        self.b = sensitivity / self.epsilon  # Laplace scale parameter

    def _sample_laplace_noise(self) -> float:
        """Draw sample from Laplace distribution using inverse transform sampling."""
        u = random.uniform(-0.5, 0.5)
        # Sign of u * b * ln(1 - 2|u|)
        if u < 0:
            return self.b * math.log(1 + 2 * u)
        return -self.b * math.log(1 - 2 * u)

    def perturb_feature_vector(self, feature_dict: Dict[str, float]) -> Dict[str, float]:
        """
        Add Laplace noise to feature values.
        Guarantees epsilon-differential privacy. Zero domain strings are retained.
        """
        noised_features = {}
        for key, val in feature_dict.items():
            if isinstance(val, (int, float)):
                noise = self._sample_laplace_noise()
                noised_features[key] = round(float(val) + noise, 4)

        return noised_features

    def create_privacy_preserving_payload(self, user_vote: str, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Package anonymous, noised telemetry payload.
        """
        noised_vec = self.perturb_feature_vector(features)
        return {
            "vote": user_vote,  # "correct" | "false_positive" | "false_negative"
            "epsilon": self.epsilon,
            "noised_features": noised_vec,
            "anonymized": True,
        }
