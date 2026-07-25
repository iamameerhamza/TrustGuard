import os
import base64
import httpx
import logging
from dotenv import load_dotenv

# Set up logger
logger = logging.getLogger(__name__)

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3/urls/"

def check_virustotal(url: str) -> dict | None:
    """Check URL against VirusTotal API.
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary with VirusTotal results or None if check failed
    """
    if not VT_API_KEY:
        logger.warning("VirusTotal API key not configured")
        return None
        
    # VT v3 API expects the URL to be base64url encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    try:
        # 5 second timeout to ensure we don't block the API
        with httpx.Client(timeout=5.0) as client:
            response = client.get(f"{VT_API_URL}{url_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                total = malicious + suspicious + harmless + undetected
                
                if total > 0:
                    vt_score = (malicious + (suspicious * 0.5)) / total
                    logger.debug(f"VirusTotal check for {url}: {malicious} malicious, {suspicious} suspicious, score: {vt_score:.4f}")
                    return {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "total": total,
                        "score": vt_score
                    }
                else:
                    logger.warning(f"VirusTotal returned empty stats for {url}")
                    return None
            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded.")
                return None
            elif response.status_code == 404:
                logger.info(f"URL not found in VirusTotal database: {url}")
                return None
            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return None
                
    except httpx.TimeoutException:
        logger.error(f"VirusTotal API timeout for URL: {url}")
        return None
    except Exception as e:
        logger.error(f"VirusTotal lookup failed for {url}: {e}")
        return None