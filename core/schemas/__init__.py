"""
Core schemas package.
Exports all shared Pydantic models for inter-module communication.
"""
from __future__ import annotations

# Evidence and verdict schemas
from core.schemas.evidence import (
    EvidenceType,
    Evidence,
    ModalityInput,
    FeatureVector,
    ModelOutput,
    ChainOfThoughtStep,
    Investigation,
    Verdict,
)

# Configuration
from core.schemas.config import Settings, FeatureFlags, settings

__all__ = [
    # Evidence
    "EvidenceType",
    "Evidence", 
    "ModalityInput",
    "FeatureVector",
    "ModelOutput",
    "ChainOfThoughtStep",
    "Investigation",
    "Verdict",
    # Config
    "Settings",
    "FeatureFlags",
    "settings",
]