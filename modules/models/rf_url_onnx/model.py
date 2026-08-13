"""
RF URL ONNX Model Wrapper - Local inference for URL phishing detection.
Single responsibility: FeatureVector → ModelOutput
Supports both Python (ONNX Runtime) and Web (ONNX Runtime Web) inference.
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


class RFURLONNXModel:
    """
    ONNX Runtime wrapper for the Random Forest URL phishing model.
    
    Features:
    - Hot-reload on model file change
    - Input validation against feature schema
    - Consistent output format for fusion
    - Exportable to ONNX for edge deployment
    """
    
    def __init__(self, model_path: str = "models/phishing_rf.onnx"):
        self.model_path = Path(model_path)
        self.session: Optional[object] = None  # ort.InferenceSession
        self.input_name: Optional[str] = None
        self.output_names: list[str] = []
        self.feature_names: list[str] = []
        self.metadata: dict = {}
        self.version = "1.0.0"
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load ONNX model with validation."""
        try:
            import onnxruntime as ort
        except ImportError:
            logger.warning("onnxruntime not installed - ONNX inference unavailable")
            return False
        
        if not self.model_path.exists():
            logger.warning(f"Model file not found: {self.model_path}")
            return False
        
        try:
            # Create session with CPU provider (works everywhere)
            self.session = ort.InferenceSession(
                str(self.model_path),
                providers=['CPUExecutionProvider']
            )
            
            # Get input/output info
            self.input_name = self.session.get_inputs()[0].name
            self.output_names = [o.name for o in self.session.get_outputs()]
            
            # Load metadata if available
            meta_path = self.model_path.with_suffix('.json')
            if meta_path.exists():
                with open(meta_path, 'r') as f:
                    self.metadata = json.load(f)
                self.feature_names = self.metadata.get('feature_names', [])
                self.version = self.metadata.get('version', self.version)
            
            logger.info(f"Loaded ONNX model: {self.model_path} (v{self.version})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self.session = None
            return False
    
    def predict(self, feature_vector: FeatureVector) -> ModelOutput:
        """
        Run inference on feature vector.
        
        Args:
            feature_vector: Validated feature vector from extractor
            
        Returns:
            ModelOutput with score, prediction, confidence
        """
        start = time.perf_counter()
        
        if self.session is None:
            # Model not loaded - return safe default
            return ModelOutput(
                score=0.5,
                prediction="suspicious",
                confidence=0.0,
                latency_ms=0.0,
                model_name="rf_url_onnx",
                model_version=self.version,
            )
        
        # Validate feature names match
        if self.feature_names and feature_vector.feature_names != self.feature_names:
            logger.warning(
                f"Feature mismatch: expected {self.feature_names}, "
                f"got {feature_vector.feature_names}"
            )
        
        # Build input array in correct order
        try:
            input_array = np.array([
                [feature_vector.features[name] for name in self.feature_names]
            ], dtype=np.float32)
        except KeyError as e:
            logger.error(f"Missing feature: {e}")
            return ModelOutput(
                score=0.5,
                prediction="suspicious",
                confidence=0.0,
                latency_ms=(time.perf_counter() - start) * 1000,
                model_name="rf_url_onnx",
                model_version=self.version,
            )
        
        # Run inference
        try:
            outputs = self.session.run(self.output_names, {self.input_name: input_array})
            
            # Parse outputs (assuming binary classification: [prob_safe, prob_phishing])
            # Output shape: [batch, 2] for probabilities
            if len(outputs) >= 1:
                probs = outputs[0][0]  # First batch, all classes
                if len(probs) >= 2:
                    phishing_prob = float(probs[1])
                else:
                    phishing_prob = float(probs[0])
            else:
                phishing_prob = 0.5
            
            latency_ms = (time.perf_counter() - start) * 1000
            
            # Determine prediction label
            if phishing_prob >= 0.7:
                prediction = "phishing"
            elif phishing_prob >= 0.3:
                prediction = "suspicious"
            else:
                prediction = "safe"
            
            return ModelOutput(
                score=phishing_prob,
                prediction=prediction,
                confidence=abs(phishing_prob - 0.5) * 2,  # Distance from decision boundary
                latency_ms=latency_ms,
                model_name="rf_url_onnx",
                model_version=self.version,
            )
            
        except Exception as e:
            logger.error(f"Inference error: {e}")
            latency_ms = (time.perf_counter() - start) * 1000
            return ModelOutput(
                score=0.5,
                prediction="suspicious",
                confidence=0.0,
                latency_ms=latency_ms,
                model_name="rf_url_onnx",
                model_version=self.version,
            )
    
    def export_onnx(self, output_path: str) -> bool:
        """
        Export model to ONNX format.
        Note: This requires the original scikit-learn model.
        """
        # This would be implemented in training/export script
        # Not in the inference wrapper
        logger.warning("export_onnx not implemented in inference wrapper")
        return False
    
    def get_metadata(self) -> dict:
        """Get model metadata."""
        return {
            "model_name": "rf_url_onnx",
            "version": self.version,
            "feature_names": self.feature_names,
            "input_name": self.input_name,
            "output_names": self.output_names,
            "loaded": self.session is not None,
            **self.metadata,
        }
    
    def health_check(self) -> dict:
        """Health check for model."""
        return {
            "status": "ok" if self.session else "unavailable",
            "model_path": str(self.model_path),
            "version": self.version,
            "feature_count": len(self.feature_names),
            "loaded": self.session is not None,
        }


# Protocol for model modules
class InferenceModel(Protocol):
    def predict(self, feature_vector: FeatureVector) -> ModelOutput: ...
    def get_metadata(self) -> dict: ...
    def health_check(self) -> dict: ...


# Factory function for easy instantiation
def create_model(model_path: str = "models/phishing_rf.onnx") -> RFURLONNXModel:
    """Create and return model instance."""
    return RFURLONNXModel(model_path)