import math
import re
import logging
import json
import os
from typing import Dict, Any
import Levenshtein
from sklearn.feature_extraction.text import HashingVectorizer
from app.core.telemetry import track_latency

# Set up logger
logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = {'login', 'secure', 'bank', 'account', 'update', 'verify', 'credential', 'password'}

# Load top brands dynamically
_BRANDS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "top_brands.json")
try:
    with open(_BRANDS_FILE, 'r') as f:
        TOP_BRANDS = json.load(f)
except Exception as e:
    logger.warning(f"Failed to load top_brands.json: {e}")
    TOP_BRANDS = []

# Pre-initialize HashingVectorizer to ensure sub-millisecond setup during inference
# n_features=256 ensures O(1) latency despite collisions
ngram_vectorizer = HashingVectorizer(analyzer='char', ngram_range=(3, 5), n_features=256, norm=None, alternate_sign=False)

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def detect_homoglyphs(domain: str) -> Dict[str, float]:
    """Detect punycode and mixed scripts."""
    is_punycode = 1.0 if domain.startswith("xn--") or ".xn--" in domain else 0.0
    
    # Calculate non-ASCII character ratio
    non_ascii_count = sum(1 for char in domain if ord(char) > 127)
    non_ascii_ratio = non_ascii_count / max(len(domain), 1)
    
    return {
        "is_punycode": is_punycode,
        "non_ascii_ratio": non_ascii_ratio
    }

def calculate_brand_spoofing(domain: str) -> float:
    """Find the minimum Levenshtein distance to any top brand. Returns a score."""
    if not TOP_BRANDS:
        return 0.0
        
    # Strip TLD and punctuation for brand comparison
    domain_clean = re.sub(r'[^a-zA-Z0-9]', '', domain.split('.')[0].lower())
    if not domain_clean:
        return 0.0
        
    min_dist = float('inf')
    for brand in TOP_BRANDS:
        dist = Levenshtein.distance(domain_clean, brand)
        if dist < min_dist:
            min_dist = dist
            
    # Risk score: Distance 1 or 2 is highly suspicious (e.g., paypa1). Distance 0 is legitimate brand.
    if min_dist == 0:
        return 0.0  # Exact match (could be legit, could be subdomain spoof, but not homoglyph)
    elif min_dist <= 2:
        return 1.0  # High risk of typosquatting/homoglyph
    else:
        return 0.0

@track_latency(module="url", stage="feature_extraction")
def extract_features(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """Extract features from a normalized URL for ML model prediction."""
    url = normalized.get("url", "")
    domain = normalized.get("domain", "")
    
    # Base structural features
    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomain_count": max(0, len(domain.split('.')) - 2),
        "has_special_chars": float(bool(re.search(r'[@\-]', domain))),
        "entropy": calculate_entropy(url),
        "suspicious_keywords": float(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()))
    }
    
    # Homoglyph / Punycode features
    homoglyph_feats = detect_homoglyphs(domain)
    features.update(homoglyph_feats)
    
    # Brand Spoofing feature
    features["brand_spoof_risk"] = calculate_brand_spoofing(domain)
    
    # Char N-Grams (256 features)
    # HashingVectorizer expects an iterable of strings
    ngram_matrix = ngram_vectorizer.transform([url])
    ngram_array = ngram_matrix.toarray()[0]
    
    for i, val in enumerate(ngram_array):
        features[f"ngram_{i}"] = float(val)
        
    logger.debug(f"Extracted {len(features)} features")
    return features