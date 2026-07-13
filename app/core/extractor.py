import math
import re
from typing import Dict, Any

SUSPICIOUS_KEYWORDS = {'login', 'secure', 'bank', 'account', 'update', 'verify', 'credential', 'password'}

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(normalized: Dict[str, Any]) -> Dict[str, Any]:
    url = normalized.get("url", "")
    domain = normalized.get("domain", "")
    
    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomain_count": max(0, len(domain.split('.')) - 2),
        "has_special_chars": bool(re.search(r'[@\-]', domain)),
        "entropy": calculate_entropy(url),
        "suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    }
