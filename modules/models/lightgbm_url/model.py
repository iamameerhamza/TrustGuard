"""
LightGBM URL Phishing Detection Model.
Primary model with RandomForest fallback for production resilience.
"""
from __future__ import annotations
import os
import json
import logging
import time
from pathlib import Path
from typing import Optional, Protocol
import numpy as np

from core.schemas import FeatureVector, ModelOutput

logger = logging.getLogger(__name__)


class LightGBMURLModel:
    """
    LightGBM model wrapper for URL phishing detection.
    
    Features:
    - Primary LightGBM model with calibrated probabilities
    - RandomForest fallback loaded as backup
    - Platt/Isotonic calibration on held-out data
    - Consistent output format for fusion
    """
    
    def __init__(self, model_path: str = "models/phishing_lightgbm.txt"):
        self.model_path = Path(model_path)
        self.booster: Optional[object] = None  # lightgbm.Booster
        self.rf_model: Optional[object] = None  # RandomForest fallback
        self.input_name = "features"
        self.output_names = ["probability"]
        self.feature_names: list[str] = []
        self.metadata: dict = {}
        self.version = "2.0.0"
        self.calibration_params: dict = {}
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load LightGBM model with RandomForest fallback."""
        try:
            import lightgbm as lgb
        except ImportError:
            logger.warning("lightgbm not installed - model unavailable")
            return False
        
        # Load metadata if available
        meta_path = self.model_path.with_suffix('.json')
        if meta_path.exists():
            with open(meta_path, 'r') as f:
                self.metadata = json.load(f)
                self.feature_names = self.metadata.get('feature_names', [])
                self.version = self.metadata.get('version', self.version)
                self.calibration_params = self.metadata.get('calibration', {})
        
        # Load LightGBM model
        if self.model_path.exists():
            try:
                self.booster = lgb.Booster(model_file=str(self.model_path))
                logger.info(f"Loaded LightGBM model: {self.model_path} (v{self.version})")
            except Exception as e:
                logger.error(f"Failed to load LightGBM model: {e}")
                self.booster = None
        
        # Load RandomForest fallback
        rf_path = self.model_path.parent / "phishing_rf.onnx"
        if rf_path.exists():
            try:
                from modules.models.rf_url_onnx.model import RFURLONNXModel
                self.rf_model = RFURLONNXModel(str(rf_path))
                logger.info("Loaded RandomForest fallback model")
            except Exception as e:
                logger.warning(f"Failed to load RF fallback: {e}")
                self.rf_model = None
        
        return self.booster is not None or self.rf_model is not None
    
    def predict(self, feature_vector: FeatureVector) -> ModelOutput:
        """
        Run inference on feature vector.
        
        Args:
            feature_vector: Validated feature vector from extractor
            
        Returns:
            ModelOutput with score, prediction, confidence
        """
        start = time.perf_counter()
        
        # Try LightGBM first
        if self.booster is not None:
            try:
                return self._predict_lightgbm(feature_vector, start)
            except Exception as e:
                logger.warning(f"LightGBM prediction failed, falling back: {e}")
        
        # Fallback to RandomForest
        if self.rf_model is not None:
            try:
                return self.rf_model.predict(feature_vector)
            except Exception as e:
                logger.error(f"RF fallback also failed: {e}")
        
        # No model available - return safe default
        latency_ms = (time.perf_counter() - start) * 1000
        return ModelOutput(
            score=0.5,
            prediction="suspicious",
            confidence=0.0,
            latency_ms=latency_ms,
            model_name="lightgbm_url",
            model_version=self.version,
        )
    
    def _predict_lightgbm(self, feature_vector: FeatureVector, start: float) -> ModelOutput:
        """Run LightGBM prediction with calibration."""
        # Build input array
        if self.feature_names:
            try:
                input_array = np.array([
                    [feature_vector.features[name] for name in self.feature_names]
                ], dtype=np.float32)
            except KeyError as e:
                logger.error(f"Missing feature: {e}")
                raise
        else:
            # Fallback to all features in order
            input_array = np.array([
                [feature_vector.features[name] for name in feature_vector.feature_names]
            ], dtype=np.float32)
        
        # Run inference
        raw_prob = self.booster.predict(input_array)[0]
        
        # Apply calibration if available
        calibrated_prob = self._apply_calibration(raw_prob)
        
        latency_ms = (time.perf_counter() - start) * 1000
        
        # Determine prediction label
        if calibrated_prob >= 0.7:
            prediction = "phishing"
        elif calibrated_prob >= 0.3:
            prediction = "suspicious"
        else:
            prediction = "safe"
        
        return ModelOutput(
            score=calibrated_prob,
            prediction=prediction,
            confidence=abs(calibrated_prob - 0.5) * 2,
            latency_ms=latency_ms,
            model_name="lightgbm_url",
            model_version=self.version,
        )
    
    def _apply_calibration(self, raw_prob: float) -> float:
        """Apply Platt scaling or isotonic calibration."""
        if not self.calibration_params:
            return raw_prob
        
        method = self.calibration_params.get('method', 'platt')
        
        if method == 'platt':
            # Platt scaling: sigmoid(A * x + B)
            A = self.calibration_params.get('A', 1.0)
            B = self.calibration_params.get('B', 0.0)
            calibrated = 1.0 / (1.0 + np.exp(-(A * raw_prob + B)))
            return float(calibrated)
        elif method == 'isotonic':
            # Isotonic regression - simplified piecewise linear
            # In production, use sklearn's IsotonicRegression
            thresholds = self.calibration_params.get('thresholds', [])
            values = self.calibration_params.get('values', [])
            
            for i, (t, v) in enumerate(zip(thresholds, values)):
                if raw_prob <= t:
                    return v
            return values[-1] if values else raw_prob
        
        return raw_prob
    
    def get_metadata(self) -> dict:
        """Get model metadata."""
        return {
            "model_name": "lightgbm_url",
            "version": self.version,
            "feature_names": self.feature_names,
            "input_name": self.input_name,
            "output_names": self.output_names,
            "loaded": self.booster is not None,
            "rf_fallback_loaded": self.rf_model is not None,
            "calibration_method": self.calibration_params.get('method', 'none'),
            **self.metadata,
        }
    
    def health_check(self) -> dict:
        """Health check for model."""
        return {
            "status": "ok" if self.booster else ("degraded" if self.rf_model else "unavailable"),
            "model_path": str(self.model_path),
            "version": self.version,
            "feature_count": len(self.feature_names),
            "loaded": self.booster is not None,
            "rf_fallback_loaded": self.rf_model is not None,
            "calibration_params": self.calibration_params,
        }


# Protocol for model modules
class InferenceModel(Protocol):
    def predict(self, feature_vector: FeatureVector) -> ModelOutput: ...
    def get_metadata(self) -> dict: ...
    def health_check(self) -> dict: ...


# Factory function for easy instantiation
def create_model(model_path: str = "models/phishing_lightgbm.txt") -> LightGBMURLModel:
    """Create and return model instance."""
    return LightGBMURLModel(model_path)
</arg_value><arg_key>task_progress</arg_key><arg_value>- [x] Confirm plan approval for Phase 1 implementation
- [x] Write VirusTotalClient + VTSignal code
- [x] Implement normalized cache key logic
- [x] Add integration tests for WHOIS and cache
- [x] Install pytest-asyncio for async test support
- [x] Add pytest-asyncio markers to async tests
- [x] Re-run tests to verify success
- [x] Phase 1 complete — VT wiring, WHOIS async migration, score fusion
- [x] Phase 2: Explore existing ML infrastructure
- [x] Phase 2: Implement LightGBM model
- [x] Phase 2: Add new features (char n-grams, homoglyph detection, brand-token Levenshtein)
- [x] Phase 2: Implement calibration
- [ ] Phase 2: Define and verify AUC/F1/p95 latency targets
</arg_value></tool_call>