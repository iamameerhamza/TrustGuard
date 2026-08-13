"""
TrustGuard Federated Intelligence - Federated Model Aggregator
Implements Federated Averaging (FedAvg) with Median Absolute Deviation (MAD) outlier filtering for global model weight updates.
"""
from __future__ import annotations
import math
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class FederatedModelAggregator:
    """Aggregates local client updates to update global baseline feature weights."""

    def __init__(self, outlier_threshold: float = 3.0):
        self.outlier_threshold = outlier_threshold

    def aggregate_updates(self, client_updates: List[Dict[str, float]]) -> Dict[str, float]:
        """
        Compute robust FedAvg across client updates.
        Filter extreme parameter outliers using Median Absolute Deviation (MAD).
        """
        if not client_updates:
            return {}

        all_keys = set().union(*client_updates)
        global_weights: Dict[str, float] = {}

        for key in all_keys:
            vals = [update[key] for update in client_updates if key in update]
            if not vals:
                continue

            if len(vals) <= 2:
                global_weights[key] = round(sum(vals) / len(vals), 4)
                continue

            # Compute median
            sorted_vals = sorted(vals)
            n = len(sorted_vals)
            median = sorted_vals[n // 2] if n % 2 != 0 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0

            # Compute Median Absolute Deviation (MAD)
            absolute_deviations = sorted([abs(v - median) for v in vals])
            mad = absolute_deviations[n // 2] if n % 2 != 0 else (absolute_deviations[n // 2 - 1] + absolute_deviations[n // 2]) / 2.0

            # Scale MAD for normal distribution consistency (1.4826)
            scaled_mad = mad * 1.4826

            if scaled_mad > 0.0001:
                filtered = [v for v in vals if (abs(v - median) / scaled_mad) <= self.outlier_threshold]
            else:
                filtered = vals

            if not filtered:
                filtered = vals

            global_weights[key] = round(sum(filtered) / len(filtered), 4)

        return global_weights
