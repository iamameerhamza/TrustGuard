"""
Configuration and feature flags.
Uses Pydantic Settings when available, or standard dataclasses fallback.
Zero dependencies on modules.
"""
from __future__ import annotations
from typing import Optional
from dataclasses import dataclass, field

try:
    from pydantic import Field
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class FeatureFlags(BaseSettings):
        """Runtime feature toggles - all disabled by default for safety."""
        model_config = SettingsConfigDict(
            env_prefix="TG_FEATURE_",
            case_sensitive=False,
            extra="ignore",
        )
        
        enable_onnx_web: bool = False
        enable_offline_mode: bool = True
        enable_local_cache: bool = True
        enable_visual_analysis: bool = False
        enable_qr_scanning: bool = False
        enable_document_analysis: bool = False
        enable_audio_analysis: bool = False
        enable_agentic_reasoning: bool = False
        enable_auto_actions: bool = False
        enable_chain_of_thought: bool = True
        enable_federated_learning: bool = False
        enable_dp_aggregation: bool = False
        enable_pq_crypto: bool = False
        enable_hybrid_signatures: bool = False
        enable_debug_logging: bool = False
        enable_metrics: bool = True

    class Settings(BaseSettings):
        """Application settings from environment."""
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            case_sensitive=False,
            extra="ignore",
        )
        
        api_host: str = "0.0.0.0"
        api_port: int = 8000
        cors_origins: str = "http://localhost:5173"
        api_key: Optional[str] = None
        model_dir: str = "models"
        rf_model_name: str = "phishing_rf.joblib"
        onnx_model_name: str = "phishing_rf.onnx"
        slm_model_path: Optional[str] = None
        virustotal_api_key: Optional[str] = None
        urlhaus_enabled: bool = True
        db_path: str = "trustguard.db"
        rate_limit_requests: int = 100
        rate_limit_window_seconds: int = 60
        log_level: str = "INFO"
        log_format: str = "json"
        features: FeatureFlags = Field(default_factory=FeatureFlags)

    settings = Settings()

except ImportError:
    @dataclass
    class FeatureFlags:
        enable_onnx_web: bool = False
        enable_offline_mode: bool = True
        enable_local_cache: bool = True
        enable_visual_analysis: bool = False
        enable_qr_scanning: bool = False
        enable_document_analysis: bool = False
        enable_audio_analysis: bool = False
        enable_agentic_reasoning: bool = False
        enable_auto_actions: bool = False
        enable_chain_of_thought: bool = True
        enable_federated_learning: bool = False
        enable_dp_aggregation: bool = False
        enable_pq_crypto: bool = False
        enable_hybrid_signatures: bool = False
        enable_debug_logging: bool = False
        enable_metrics: bool = True

    @dataclass
    class Settings:
        api_host: str = "0.0.0.0"
        api_port: int = 8000
        cors_origins: str = "http://localhost:5173"
        api_key: Optional[str] = None
        model_dir: str = "models"
        rf_model_name: str = "phishing_rf.joblib"
        onnx_model_name: str = "phishing_rf.onnx"
        slm_model_path: Optional[str] = None
        virustotal_api_key: Optional[str] = None
        urlhaus_enabled: bool = True
        db_path: str = "trustguard.db"
        rate_limit_requests: int = 100
        rate_limit_window_seconds: int = 60
        log_level: str = "INFO"
        log_format: str = "json"
        features: FeatureFlags = field(default_factory=FeatureFlags)

    settings = Settings()