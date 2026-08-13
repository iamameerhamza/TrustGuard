"""
URL Intake Module - Normalize and validate raw URL input.
Single responsibility: Raw string → ModalityInput
Pure functions, no external dependencies.
"""
from __future__ import annotations
import re
import logging
from urllib.parse import urlparse, parse_qs
from typing import Optional
from core.schemas import ModalityInput, Evidence, EvidenceType
from datetime import datetime

logger = logging.getLogger(__name__)


class URLIntake:
    """
    Normalize and validate URLs for downstream processing.
    
    Features:
    - Scheme normalization (http/https)
    - IDN/punycode handling
    - Path/query normalization
    - Basic validation
    - Metadata extraction
    """
    
    # Common URL schemes
    VALID_SCHEMES = frozenset({"http", "https"})
    
    # Maximum URL length (RFC 3986 suggests no limit, but browsers limit ~2MB)
    MAX_URL_LENGTH = 2048
    
    def __init__(self):
        self.version = "1.0.0"
    
    def accept(self, raw_url: str, source: str = "api") -> ModalityInput:
        """
        Accept raw URL string and return normalized ModalityInput.
        
        Args:
            raw_url: Raw URL string from user/input
            source: Source identifier (api, browser_extension, email_gateway, etc.)
            
        Returns:
            ModalityInput with normalized URL and metadata
            
        Raises:
            ValueError: If URL is invalid or cannot be normalized
        """
        if not raw_url or not isinstance(raw_url, str):
            raise ValueError("URL must be a non-empty string")
        
        raw_url = raw_url.strip()
        
        if len(raw_url) > self.MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {self.MAX_URL_LENGTH}")
        
        # Normalize URL
        normalized = self._normalize_url(raw_url)
        
        # Validate
        self._validate(normalized)
        
        # Extract components
        parsed = urlparse(normalized)
        
        content = {
            "url": normalized,
            "scheme": parsed.scheme,
            "domain": parsed.netloc.lower(),
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "fragment": parsed.fragment or "",
            "port": parsed.port,
            "username": parsed.username,
            "password": parsed.password,  # Will be None in most cases
        }
        
        # Remove password from stored content
        if content["password"]:
            content["password"] = "[REDACTED]"
        
        metadata = {
            "original_url": raw_url,
            "normalized": normalized != raw_url,
            "has_credentials": bool(parsed.username or parsed.password),
            "is_idn": self._is_idn(parsed.netloc),
            "source": source,
        }
        
        return ModalityInput(
            modality="url",
            source=source,
            content=content,
            metadata=metadata,
            timestamp=datetime.utcnow(),
        )
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to standard form."""
        # Add scheme if missing (default to https)
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
            url = "https://" + url
        
        # Parse
        parsed = urlparse(url)
        
        # Normalize scheme to lowercase
        scheme = parsed.scheme.lower()
        if scheme not in self.VALID_SCHEMES:
            scheme = "https"  # Default to https
        
        # Normalize netloc (domain + port)
        netloc = parsed.netloc.lower()
        
        # Remove default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        
        # Normalize path
        path = parsed.path or "/"
        # Remove duplicate slashes
        path = re.sub(r'/+', '/', path)
        # Ensure leading slash
        if not path.startswith("/"):
            path = "/" + path
        
        # Normalize query (keep as-is for feature extraction)
        query = parsed.query
        
        # Reconstruct
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"
        
        return normalized
    
    def _validate(self, url: str) -> None:
        """Validate normalized URL."""
        parsed = urlparse(url)
        
        if not parsed.scheme or parsed.scheme not in self.VALID_SCHEMES:
            raise ValueError(f"Invalid scheme: {parsed.scheme}")
        
        if not parsed.netloc:
            raise ValueError("Missing domain/host")
        
        # Basic domain validation
        domain = parsed.netloc.split(":")[0]  # Remove port
        if not self._is_valid_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation."""
        if not domain or len(domain) > 253:
            return False
        
        # Check each label
        labels = domain.split(".")
        for label in labels:
            if not label or len(label) > 63:
                return False
            # Valid characters: alphanumeric and hyphen (not at start/end)
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                # Allow punycode
                if not label.startswith("xn--"):
                    return False
        
        return True
    
    def _is_idn(self, domain: str) -> bool:
        """Check if domain is internationalized (contains non-ASCII or punycode)."""
        if not domain:
            return False
        # Check for punycode prefix
        if "xn--" in domain:
            return True
        # Check for non-ASCII
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True
    
    def supported_schemes(self) -> list[str]:
        """Return supported URL schemes."""
        return list(self.VALID_SCHEMES)
    
    def health_check(self) -> dict:
        """Health check for intake module."""
        return {
            "status": "ok",
            "version": self.version,
            "supported_schemes": list(self.VALID_SCHEMES),
            "max_url_length": self.MAX_URL_LENGTH,
        }


# Protocol for intake modules
class IntakeModule:
    def accept(self, raw_input: str, source: str = "api") -> ModalityInput: ...
    def supported_schemes(self) -> list[str]: ...
    def health_check(self) -> dict: ...