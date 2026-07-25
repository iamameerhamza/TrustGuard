import urllib.parse
import ipaddress
from typing import Dict, Any
from fastapi import HTTPException

def normalize_url(url: str) -> Dict[str, Any]:
    """
    Cleans a raw URL string, handling missing schemas and extracting domain/path information.
    """
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL exceeds maximum allowed length")
        
    if not url:
        raise ValueError("URL cannot be empty")
        
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        
        # Basic SSRF prevention: reject localhost and private IP addresses
        hostname = parsed.hostname
        if hostname:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback:
                    raise HTTPException(status_code=400, detail="Internal/private IPs are not allowed")
            except ValueError:
                # It's a regular domain name, which is fine.
                if hostname in ("localhost", "127.0.0.1", "::1"):
                    raise HTTPException(status_code=400, detail="Localhost is not allowed")
        
        scheme = parsed.scheme
        path = parsed.path if parsed.path else "/"
        query = parsed.query
        
        normalized_url = f"{scheme}://{netloc}{path}"
        if query:
            normalized_url += f"?{query}"
            
        domain = netloc.split(':')[0]
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else ""
            
        return {
            "url": normalized_url,
            "domain": domain,
            "tld": tld,
            "path": path,
            "query": query,
            "scheme": scheme
        }
    except ValueError as e:
        # Catch errors from ipaddress parsing that aren't caught by the inner try
        raise e
    except Exception as e:
        return {
            "url": url,
            "domain": "",
            "tld": "",
            "path": "",
            "query": "",
            "scheme": ""
        }
