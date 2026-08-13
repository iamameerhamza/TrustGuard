"""
Quick Scan Pipeline - URL-only fast path.
Composes: Intake → Extractor → Model → Verdict
Zero external dependencies, fully local, <100ms target latency.
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass
from typing import Optional

from modules.intake.url_intake.intake import URLIntake
from modules.extractors.url_features.extractor import URLFeatureExtractor
from modules.models.rf_url_onnx.model import RFURLONNXModel
from core.schemas import ModalityInput, FeatureVector, ModelOutput, Evidence, EvidenceType, Verdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """Context passed through pipeline stages."""
    modality_input: Optional[ModalityInput] = None
    feature_vector: Optional[FeatureVector] = None
    model_output: Optional[ModelOutput] = None
    evidence: list[Evidence] = None
    errors: list[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.errors is None:
            self.errors = []


class QuickScanPipeline:
    """
    Fast URL-only scanning pipeline.
    
    Flow:
    1. Intake: Normalize & validate URL
    2. Extract: Compute lexical/structural features
    3. Model: ONNX Runtime inference
    4. Verdict: Fuse evidence into final verdict
    """
    
    def __init__(
        self,
        intake: Optional[URLIntake] = None,
        extractor: Optional[URLFeatureExtractor] = None,
        model: Optional[RFURLONNXModel] = None,
    ):
        self.intake = intake or URLIntake()
        self.extractor = extractor or URLFeatureExtractor()
        self.model = model or RFURLONNXModel()
        self.version = "1.0.0"
    
    async def run(self, url: str, source: str = "api") -> Verdict:
        """
        Execute full quick scan pipeline.
        
        Args:
            url: Raw URL string to analyze
            source: Source identifier (api, browser_extension, etc.)
            
        Returns:
            Verdict with score, prediction, evidence, chain_of_thought
        """
        start_time = time.perf_counter()
        ctx = ScanContext()
        
        # Stage 1: Intake
        try:
            ctx.modality_input = self.intake.accept(url, source=source)
            ctx.evidence.append(Evidence(
                type=EvidenceType.URL_LEXICAL,
                source_module="url_intake",
                timestamp=datetime.utcnow(),
                confidence=1.0,
                description=f"URL normalized: {ctx.modality_input.content['url']}",
                raw_data={"normalized_url": ctx.modality_input.content["url"]},
                tags=["intake", "normalized"],
            ))
        except Exception as e:
            ctx.errors.append(f"Intake failed: {e}")
            logger.error(f"Intake error for {url}: {e}")
            return self._error_verdict(url, ctx.errors, start_time)
        
        # Stage 2: Feature Extraction
        try:
            ctx.feature_vector = self.extractor.extract(ctx.modality_input)
            ctx.evidence.append(Evidence(
                type=EvidenceType.URL_LEXICAL,
                source_module="url_features",
                timestamp=datetime.utcnow(),
                confidence=0.95,
                description=f"Extracted {len(ctx.feature_vector.features)} lexical features",
                raw_data={
                    "feature_names": ctx.feature_vector.feature_names,
                    "extractor_version": ctx.feature_vector.extractor_version,
                },
                tags=["features", "lexical"],
            ))
        except Exception as e:
            ctx.errors.append(f"Feature extraction failed: {e}")
            logger.error(f"Feature extraction error: {e}")
            return self._error_verdict(url, ctx.errors, start_time)
        
        # Stage 3: Model Inference
        try:
            ctx.model_output = self.model.predict(ctx.feature_vector)
            ctx.evidence.append(Evidence(
                type=EvidenceType.ML_SCORE,
                source_module="rf_url_onnx",
                timestamp=datetime.utcnow(),
                confidence=ctx.model_output.confidence,
                description=f"ML model score: {ctx.model_output.score:.3f} ({ctx.model_output.prediction})",
                raw_data={
                    "score": ctx.model_output.score,
                    "prediction": ctx.model_output.prediction,
                    "latency_ms": ctx.model_output.latency_ms,
                    "model_version": self.model.version,
                },
                tags=["ml", "inference"],
            ))
        except Exception as e:
            ctx.errors.append(f"Model inference failed: {e}")
            logger.error(f"Model inference error: {e}")
            return self._error_verdict(url, ctx.errors, start_time)
        
        # Stage 4: Verdict Fusion
        verdict = self._fuse_verdict(url, ctx, start_time)
        return verdict
    
    def _fuse_verdict(self, url: str, ctx: ScanContext, start_time: float) -> Verdict:
        """Fuse evidence into final verdict."""
        total_latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Primary signal: ML model
        ml_score = ctx.model_output.score if ctx.model_output else 0.5
        ml_pred = ctx.model_output.prediction if ctx.model_output else "suspicious"
        
        # Risk score (0-100)
        risk_score = int(ml_score * 100)
        
        # Determine final prediction
        if risk_score >= 70:
            final_prediction = "phishing"
        elif risk_score >= 30:
            final_prediction = "suspicious"
        else:
            final_prediction = "safe"
        
        # Build chain of thought
        chain_of_thought = [
            f"URL normalized and validated: {ctx.modality_input.content['url']}",
            f"Extracted {len(ctx.feature_vector.features)} lexical/structural features",
            f"Random Forest model (ONNX) predicted: {ml_pred} (score: {ml_score:.3f})",
            f"Risk score: {risk_score}/100 → {final_prediction}",
        ]
        
        # Add feature highlights
        if ctx.feature_vector:
            features = ctx.feature_vector.features
            if features.get("brand_impersonation_score", 0) > 0.5:
                chain_of_thought.append(
                    f"Brand impersonation detected (score: {features['brand_impersonation_score']:.2f})"
                )
            if features.get("punycode_detected", 0) > 0:
                chain_of_thought.append("Punycode detected (possible homograph attack)")
            if features.get("has_suspicious_tld", 0) > 0:
                chain_of_thought.append(f"High-risk TLD detected")
            if features.get("suspicious_keyword_count", 0) > 2:
                chain_of_thought.append(f"Multiple suspicious keywords ({int(features['suspicious_keyword_count'])})")
        
        return Verdict(
            url=url,
            risk_score=risk_score,
            prediction=final_prediction,
            confidence=ctx.model_output.confidence if ctx.model_output else 0.0,
            latency_ms=total_latency_ms,
            evidence=ctx.evidence,
            chain_of_thought=chain_of_thought,
            model_outputs={
                "rf_url_onnx": {
                    "score": ml_score,
                    "prediction": ml_pred,
                    "latency_ms": ctx.model_output.latency_ms if ctx.model_output else 0,
                }
            },
            pipeline_version=self.version,
            timestamp=datetime.utcnow(),
            errors=ctx.errors if ctx.errors else None,
        )
    
    def _error_verdict(self, url: str, errors: list[str], start_time: float) -> Verdict:
        """Generate safe fallback verdict on error."""
        total_latency_ms = (time.perf_counter() - start_time) * 1000
        return Verdict(
            url=url,
            risk_score=50,  # Suspicious by default on error
            prediction="suspicious",
            confidence=0.0,
            latency_ms=total_latency_ms,
            evidence=[],
            chain_of_thought=[f"Pipeline error: {err}" for err in errors],
            model_outputs={},
            pipeline_version=self.version,
            timestamp=datetime.utcnow(),
            errors=errors,
        )
    
    def health_check(self) -> dict:
        """Check pipeline component health."""
        return {
            "intake": "ok",
            "extractor": "ok",
            "model": "ok" if self.model.session else "unavailable",
            "model_version": self.model.version,
            "pipeline_version": self.version,
        }


# Synchronous wrapper for simple use cases
def quick_scan_sync(url: str, source: str = "api") -> Verdict:
    """Synchronous quick scan (for CLI, tests)."""
    import asyncio
    pipeline = QuickScanPipeline()
    return asyncio.run(pipeline.run(url, source))