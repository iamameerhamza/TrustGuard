"""
URL Feature Extractor - Pure lexical and structural features.
Single responsibility: ModalityBundle → FeatureVector
No external dependencies, pure functions, fully testable.
"""
from __future__ import annotations
import math
import re
import hashlib
from typing import Protocol, List
from core.schemas import FeatureVector, ModalityInput, Evidence, EvidenceType
from datetime import datetime


class URLFeatureExtractor:
    """Extract numerical features from normalized URL for ML inference."""
    
    # Suspicious keywords (lowercase)
    SUSPICIOUS_KEYWORDS = frozenset({
        'login', 'secure', 'bank', 'account', 'update', 'verify', 
        'credential', 'password', 'signin', 'signin', 'auth', 'authenticate',
        'confirm', 'validate', 'security', 'wallet', 'crypto', 'bitcoin',
        'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
        'instagram', 'twitter', 'linkedin', 'github', 'dropbox', 'onedrive',
        'office365', 'outlook', 'webmail', 'mail', 'email', 'inbox',
        'suspended', 'locked', 'disabled', 'expired', 'urgent', 'immediate',
        'action', 'required', 'verify', 'validation', 'unusual', 'activity'
    })
    
    # High-risk TLDs
    HIGH_RISK_TLDS = frozenset({
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work',
        'date', 'racing', 'download', 'stream', 'science', 'loan',
        'win', 'party', 'review', 'trade', 'bid', 'cricket', 'faith'
    })
    
    # Known brand domains (for impersonation detection)
    BRAND_DOMAINS = frozenset({
        'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
        'amazon.com', 'paypal.com', 'github.com', 'twitter.com',
        'instagram.com', 'linkedin.com', 'netflix.com', 'spotify.com',
        'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com',
        'zoom.us', 'teams.microsoft.com', 'webex.com', 'atlassian.com',
        'jira.com', 'confluence.com', 'bitbucket.org', 'gitlab.com'
    })
    
    def __init__(self):
        self.version = "1.0.0"
        self._feature_names = [
            "url_length",
            "domain_length", 
            "subdomain_count",
            "path_length",
            "query_length",
            "has_special_chars",
            "has_at_symbol",
            "has_dash_in_domain",
            "entropy",
            "suspicious_keyword_count",
            "is_ip_address",
            "has_port",
            "tld_risk_score",
            "brand_impersonation_score",
            "punycode_detected",
            "subdomain_entropy",
            "path_entropy",
            "query_param_count",
            "has_suspicious_tld",
            "url_hash_prefix",  # For privacy-preserving blocklist checks
            "char_3gram_count",
            "char_5gram_count",
            "char_ngram_entropy",
            "homoglyph_count",
            "brand_levenshtein_distance"
        ]
        self.feature_names_list = self._feature_names
    
    def extract(self, modality_input: ModalityInput) -> FeatureVector:
        """
        Extract features from normalized URL input.
        Pure function - no side effects, no external calls.
        
        Args:
            modality_input: Normalized URL from intake module
            
        Returns:
            FeatureVector with ordered features matching model expectation
        """
        if modality_input.modality != "url":
            raise ValueError(f"Expected modality 'url', got '{modality_input.modality}'")
        
        content = modality_input.content
        url = content.get("url", "")
        domain = content.get("domain", "")
        path = content.get("path", "")
        query = content.get("query", "")
        
        # Extract all features
        features = {
            "url_length": float(len(url)),
            "domain_length": float(len(domain)),
            "subdomain_count": float(self._count_subdomains(domain)),
            "path_length": float(len(path)),
            "query_length": float(len(query)),
            "has_special_chars": float(self._has_special_chars(domain)),
            "has_at_symbol": float('@' in url),
            "has_dash_in_domain": float('-' in domain if domain else False),
            "entropy": self._calculate_entropy(url),
            "suspicious_keyword_count": float(self._count_suspicious_keywords(url)),
            "is_ip_address": float(self._is_ip_address(domain)),
            "has_port": float(content.get("port") is not None),
            "tld_risk_score": self._get_tld_risk_score(domain),
            "brand_impersonation_score": self._get_brand_impersonation_score(domain, url),
            "punycode_detected": float(self._has_punycode(domain)),
            "subdomain_entropy": self._calculate_entropy('.'.join(domain.split('.')[:-2])) if self._count_subdomains(domain) > 0 else 0.0,
            "path_entropy": self._calculate_entropy(path),
            "query_param_count": float(len([p for p in query.split('&') if p]) if query else 0),
            "has_suspicious_tld": float(self._has_suspicious_tld(domain)),
            "url_hash_prefix": self._url_hash_prefix(url),
            "char_3gram_count": self._count_char_ngrams(url, 3),
            "char_5gram_count": self._count_char_ngrams(url, 5),
            "char_ngram_entropy": self._calculate_char_ngram_entropy(url, 3),  # using 3-grams for entropy
            "homoglyph_count": self._calculate_homoglyph_score(domain),
            "brand_levenshtein_distance": self._calculate_brand_levenshtein(domain),
        }
        
        # Validate all expected features present
        for name in self._feature_names:
            if name not in features:
                features[name] = 0.0
        
        return FeatureVector(
            features=features,
            feature_names=self._feature_names,
            extractor_version=self.version,
            timestamp=datetime.utcnow(),
        )
    
    def _count_subdomains(self, domain: str) -> int:
        """Count subdomain levels (excluding TLD and SLD)."""
        if not domain:
            return 0
        parts = domain.split('.')
        # Remove TLD (last part) and SLD (second to last)
        # e.g., "sub.example.com" → 1 subdomain ("sub")
        return max(0, len(parts) - 2)
    
    def _has_special_chars(self, domain: str) -> bool:
        """Check for special characters in domain (excluding dots and hyphens)."""
        if not domain:
            return False
        # Allow alphanumeric, dots, hyphens
        return bool(re.search(r'[^a-zA-Z0-9.\-]', domain))
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        entropy = 0.0
        for char in set(text):
            p_x = float(text.count(char)) / len(text)
            entropy += -p_x * math.log2(p_x)
        return entropy
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """Count suspicious keywords in URL (case-insensitive)."""
        url_lower = url.lower()
        return sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        if not domain:
            return False
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(ip_pattern.match(domain))
    
    def _get_tld_risk_score(self, domain: str) -> float:
        """Get risk score based on TLD (0.0 = safe, 1.0 = high risk)."""
        if not domain:
            return 0.0
        tld = domain.split('.')[-1].lower()
        if tld in self.HIGH_RISK_TLDS:
            return 0.8
        # Common safe TLDs
        if tld in {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'ai'}:
            return 0.1
        return 0.3  # Unknown TLD - moderate risk
    
    def _get_brand_impersonation_score(self, domain: str, url: str) -> float:
        """Detect brand impersonation (typosquatting, subdomain spoofing)."""
        if not domain:
            return 0.0
        
        domain_lower = domain.lower()
        url_lower = url.lower()
        
        # Check if brand appears in subdomain (e.g., google.com.phishing.site)
        for brand in self.BRAND_DOMAINS:
            brand_base = brand.split('.')[0]  # e.g., "google"
            if f"{brand_base}." in domain_lower and not domain_lower.endswith(brand):
                return 0.9  # High confidence impersonation
        
        # Check for typosquatting (edit distance would be better but heavier)
        # Simple heuristic: brand name with extra chars in domain
        for brand in self.BRAND_DOMAINS:
            brand_base = brand.split('.')[0]
            if brand_base in domain_lower and not domain_lower.endswith(brand):
                # Check if it's a subdomain like "google.phishersite.com"
                if domain_lower.count('.') >= 2:
                    return 0.7
        
        return 0.0
    
    def _has_punycode(self, domain: str) -> bool:
        """Detect punycode (xn--) indicating homograph attacks."""
        return 'xn--' in domain.lower()
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain uses a suspicious TLD."""
        if not domain:
            return False
        tld = domain.split('.')[-1].lower()
        return tld in self.HIGH_RISK_TLDS
    
    def _url_hash_prefix(self, url: str, length: int = 8) -> float:
        """
        Generate URL hash prefix for privacy-preserving blocklist checks.
        Returns first 8 chars of SHA-256 as float (0-1 normalized).
        """
        hash_hex = hashlib.sha256(url.encode()).hexdigest()[:length]
        # Normalize to 0-1 range
        return int(hash_hex, 16) / (16 ** length)
    
    def _generate_char_ngrams(self, text: str, n: int) -> List[str]:
        """Generate character n-grams from text."""
        ngrams = []
        for i in range(len(text) - n + 1):
            ngram = text[i:i+n]
            ngrams.append(ngram)
        return ngrams
    
    def _count_char_ngrams(self, text: str, n: int) -> int:
        """Count occurrences of character n-grams."""
        ngrams = self._generate_char_ngrams(text, n)
        return len(ngrams)
    
    def _calculate_char_ngram_entropy(self, text: str, n: int) -> float:
        """Calculate entropy of character n-grams."""
        ngrams = self._generate_char_ngrams(text, n)
        if not ngrams:
            return 0.0
        
        # Count occurrences of each n-gram
        ngram_counts = {}
        for ngram in ngrams:
            ngram_counts[ngram] = ngram_counts.get(ngram, 0) + 1
        
        # Calculate probabilities
        total = len(ngrams)
        probabilities = {ngram: count/total for ngram, count in ngram_counts.items()}
        
        # Calculate entropy
        entropy = 0.0
        for prob in probabilities.values():
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _calculate_homoglyph_score(self, domain: str) -> float:
        """Calculate homoglyph score (0.0 = clean, 1.0 = many homoglyphs)."""
        if not domain:
            return 0.0
        
        # Define common homoglyph substitutions
        homoglyphs = {
            'l': ['1', 'I'],
            '1': ['l', 'I'],
            'o': ['0', 'O'],
            '0': ['o', 'O'],
            's': ['5', '§'],
            '5': ['s'],
            'a': ['@', '4'],
            '@': ['a'],
            '4': ['a'],
            'e': ['3', '€'],
            '3': ['e'],
            't': ['7', '+'],
            '7': ['t'],
            'b': ['6', 'g'],
            '6': ['b'],
            'g': ['b'],
            'i': ['l', 'I'],
            'l': ['i', 'I'],
            'I': ['l', 'i']
        }
        
        domain_lower = domain.lower()
        score = 0.0
        count = 0
        
        # Check each character in the domain
        for i, char in enumerate(domain_lower):
            if char in homoglyphs:
                # Check if the next character is a homoglyph substitute
                if i + 1 < len(domain_lower):
                    next_char = domain_lower[i + 1]
                    if next_char in homoglyphs.get(char, []):
                        count += 1
                        score += 0.1  # Each homoglyph pair adds 0.1 to the score
        
        # Cap the score at 1.0
        return min(1.0, score)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        # Swap strings if needed so that len(s1) >= len(s2)
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        # Previous row of distances
        previous_row = list(range(len(s2) + 1))
        
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = previous_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _calculate_brand_levenshtein(self, domain: str) -> float:
        """Calculate Levenshtein distance between domain and known brand names."""
        if not domain:
            return 1.0  # Maximum distance
        
        domain_lower = domain.lower()
        min_distance = float('inf')
        
        # Check against known brand domains
        for brand in self.BRAND_DOMAINS:
            brand_base = brand.split('.')[0].lower()  # Get the main brand name
            distance = self._levenshtein_distance(domain_lower, brand_base)
            min_distance = min(min_distance, distance)
        
        # Normalize the distance to a score between 0.0 and 1.0
        # We'll consider a distance of 0 as perfect match (score 1.0)
        # and a distance of max_length as worst match (score 0.0)
        max_possible_distance = max(len(domain_lower), max(len(brand) for brand in self.BRAND_DOMAINS))
        normalized_distance = 1.0 - (min_distance / max_possible_distance)
        
        return max(0.0, min(1.0, normalized_distance))
    
    def feature_names(self) -> list[str]:
        """Return ordered feature names for model validation."""
        return self._feature_names.copy()


# Protocol for extractor modules
class FeatureExtractor(Protocol):
    def extract(self, modality_input: ModalityInput) -> FeatureVector: ...
    def feature_names(self) -> list[str]: ...