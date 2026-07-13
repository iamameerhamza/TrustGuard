import urllib.parse
from typing import Dict, Any

def normalize_url(url: str) -> Dict[str, Any]:
    """
    Cleans a raw URL string, handling missing schemas and extracting domain/path information.
    """
    if not url:
        raise ValueError("URL cannot be empty")
        
    url = url.strip()
    
    # Simple check to add schema if it doesn't look like one is present
    if not url.lower().startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urllib.parse.urlparse(url)
    
    netloc = parsed.netloc.lower()
    
    # Split domain and port if present
    domain = netloc.split(':')[0]
    
    # Attempt to extract TLD (simple version, not full public suffix list yet)
    parts = domain.split('.')
    tld = parts[-1] if len(parts) > 1 else ""
    
    path = parsed.path if parsed.path else "/"
    query = parsed.query
    
    return {
        "url": url,
        "domain": domain,
        "tld": tld,
        "path": path,
        "query": query,
        "scheme": parsed.scheme
    }
