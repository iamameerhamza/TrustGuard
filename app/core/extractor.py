import math
import re
import logging
from typing import Dict, Any
from app.modules.whois_checker import cached_whois, score_domain_age

# Set up logger
logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = {'login', 'secure', 'bank', 'account', 'update', 'verify', 'credential', 'password'}

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.
    
    Args:
        text: Input string to calculate entropy for
        
    Returns:
        Entropy value as float
    """
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """Extract features from a normalized URL for ML model prediction.
    
    Args:
        normalized: Dictionary containing normalized URL components
        
    Returns:
        Dictionary of features for ML model
    """
    url = normalized.get("url", "")
    domain = normalized.get("domain", "")
    
    try:
        age_days = cached_whois(domain)
        whois_result = score_domain_age(age_days)
        logger.debug(f"Extracted features for domain {domain}: age_days={age_days}")
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for domain {domain}: {e}")
        age_days = None
        whois_result = {"score": 0.0}
    
    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomain_count": max(0, len(domain.split('.')) - 2),
        "has_special_chars": bool(re.search(r'[@\-]', domain)),
        "entropy": calculate_entropy(url),
        "suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()),
        "domain_age_days": age_days,
        "domain_age_score": whois_result["score"]
    }
    
    logger.debug(f"Extracted features: {features}")
    return features