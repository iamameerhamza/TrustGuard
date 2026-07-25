import logging

# Set up logger
logger = logging.getLogger(__name__)

def explain(features: dict, is_blacklisted: bool = False, ml_score: float | None = None, vt_score: float | None = None) -> list[str]:
    """Generate human-readable explanations for URL risk assessment.
    
    Args:
        features: Dictionary of URL features
        is_blacklisted: Whether URL is found in threat intelligence blacklists
        ml_score: ML model probability score (0-1) or None
        vt_score: VirusTotal score (0-1) or None
        
    Returns:
        List of explanation strings
    """
    logger.debug(f"Generating explanation for features: {features}")
    reasons = []
    
    try:
        if is_blacklisted:
            reasons.append("URL was found in known threat intelligence blacklists (OpenPhish / URLHaus).")
            logger.debug("Added blacklist reason")
            return reasons
            
        keywords_count = features.get("suspicious_keywords", 0)
        if keywords_count > 0:
            reasons.append(f"URL contains {keywords_count} suspicious keyword(s) (+{keywords_count * 10} risk).")
            logger.debug(f"Added keyword reason: {keywords_count}")
            
        entropy = features.get("entropy", 0.0)
        if entropy > 4.5:
            reasons.append(f"High character entropy ({entropy:.2f}) detected, suggesting an obfuscated or random string (+20 risk).")
            logger.debug(f"Added entropy reason: {entropy:.2f}")
            
        url_length = features.get("url_length", 0)
        if url_length > 75:
            reasons.append(f"URL is unusually long ({url_length} characters) (+10 risk).")
            logger.debug(f"Added URL length reason: {url_length}")
            
        domain_length = features.get("domain_length", 0)
        if domain_length > 25:
            reasons.append(f"Domain name is unusually long ({domain_length} characters) (+10 risk).")
            logger.debug(f"Added domain length reason: {domain_length}")
            
        subdomain_count = features.get("subdomain_count", 0)
        if subdomain_count > 2:
            reasons.append(f"URL contains a high number of subdomains ({subdomain_count}) (+15 risk).")
            logger.debug(f"Added subdomain count reason: {subdomain_count}")
            
        if features.get("has_special_chars", False):
            reasons.append("Domain name contains suspicious special characters (@ or -) (+10 risk).")
            logger.debug("Added special chars reason")
            
        domain_age_days = features.get("domain_age_days")
        if domain_age_days is not None:
            if domain_age_days < 3:
                reasons.append(f"This domain is brand new ({domain_age_days} days old), which is highly suspicious and typical of temporary phishing infrastructure (+40 risk).")
                logger.debug(f"Added new domain reason: {domain_age_days} days")
            elif domain_age_days < 30:
                reasons.append(f"This domain is relatively new ({domain_age_days} days old), suggesting potential risk (+25 risk).")
                logger.debug(f"Added recent domain reason: {domain_age_days} days")
        
        if ml_score is not None:
            reasons.append(f"Machine learning model calculated a {ml_score*100:.1f}% probability of phishing.")
            logger.debug(f"Added ML score reason: {ml_score:.4f}")
            
        if vt_score is not None and vt_score > 0:
            reasons.append(f"VirusTotal Consensus: Multiple security vendors have flagged this URL as malicious (VT Score: {vt_score:.2f}).")
            logger.debug(f"Added VT score reason: {vt_score:.4f}")
            
        if not reasons:
            reasons.append("No suspicious traits detected.")
            logger.debug("No reasons found, added default message")
            
        logger.debug(f"Generated {len(reasons)} explanation reasons")
        return reasons
    except Exception as e:
        logger.error(f"Error generating explanation: {e}")
        return ["Error generating explanation"]