"""
TrustGuard Core Schemas - Standardized Evidence & Verdict Schema
Defines machine-readable, audit-proven threat evidence containers across all inspection layers.
"""
from __future__ import annotations
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    WHOIS = "whois"
    SSL = "ssl"
    IP = "ip"
    LEXICAL = "lexical"
    THREAT_FEED = "threat_feed"
    VISUAL_SPOOF = "visual_spoof"
    QR_PAYLOAD = "qr_payload"
    DOCUMENT_MALWARE = "document_malware"
    VISHING_AUDIO = "vishing_audio"
    AGENTIC_TOOL = "agentic_tool"


@dataclass
class Evidence:
    """Legacy Evidence dataclass for modality extractors."""
    evidence_type: str
    content: Dict[str, Any]
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0


@dataclass
class ModalityInput:
    """Standardized input payload for feature extractors."""
    modality: str  # "url" | "webpage" | "email"
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FeatureVector:
    """Extracted feature vector for ML model consumption."""
    features: Dict[str, float]
    feature_names: List[str]
    extractor_version: str = "1.0.0"
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ModelOutput:
    """Output from machine learning risk scoring models."""
    prediction: str  # "safe" | "phishing" | "suspicious"
    risk_score: float  # 0.0 - 100.0
    probabilities: Dict[str, float]
    model_version: str
    model_name: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ChainOfThoughtStep:
    step_number: int
    tool_name: str
    action: str
    result: Dict[str, Any]
    reasoning: str


@dataclass
class Investigation:
    investigation_id: str
    target: str
    steps: List[ChainOfThoughtStep]
    final_verdict: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Verdict:
    url: str
    prediction: str
    risk_score: float
    confidence: float
    explanation: List[str]
    features: Dict[str, float]
    scanned_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class EvidenceItem:
    """Single evidence item produced by an inspector or tool."""
    evidence_id: str
    evidence_type: EvidenceType
    source_layer: str
    confidence: float
    severity: SeverityLevel
    raw_observation: Dict[str, Any]
    explanation: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VerdictSummary:
    """Consolidated threat verdict produced by evidence engine."""
    target: str
    overall_risk_score: float
    verdict_label: str  # "safe" | "suspicious" | "phishing" | "malicious"
    confidence: float
    primary_risk_drivers: List[str]
    evidence_list: List[EvidenceItem]
    remediation_guidance: str
    created_at: datetime = field(default_factory=datetime.utcnow)