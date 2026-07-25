import logging

# Set up logger
logger = logging.getLogger(__name__)

def calculate_risk(features: dict) -> dict:
    """Calculate risk score and prediction based on URL features.
    
    Args:
        features: Dictionary of URL features extracted by extractor
        
    Returns:
        Dictionary containing risk_score (0-100) and prediction (safe/suspicious/phishing)
    """
    risk_score = 0
    
    try:
        # Keyword risk: 15 points per keyword (calibrated)
        keywords_count = features.get("suspicious_keywords", 0)
        risk_score += keywords_count * 15
        logger.debug(f"Keyword risk: {keywords_count} keywords -> +{keywords_count * 15}")
        
        # Entropy risk: high entropy is often indicative of random strings (e.g. DGA)
        entropy = features.get("entropy", 0.0)
        if entropy > 4.5:
            risk_score += 20
            logger.debug(f"Entropy risk: {entropy:.2f} > 4.5 -> +20")
        
        # URL length risk
        url_length = features.get("url_length", 0)
        if url_length > 75:
            risk_score += 10
            logger.debug(f"URL length risk: {url_length} > 75 -> +10")
        
        # Domain length risk
        domain_length = features.get("domain_length", 0)
        if domain_length > 25:
            risk_score += 15
            logger.debug(f"Domain length risk: {domain_length} > 25 -> +15")
        
        # Subdomain count risk
        subdomain_count = features.get("subdomain_count", 0)
        if subdomain_count > 2:
            risk_score += 20
            logger.debug(f"Subdomain count risk: {subdomain_count} > 2 -> +20")
        
        # Special characters in domain
        if features.get("has_special_chars", False):
            risk_score += 10
            logger.debug("Special chars in domain -> +10")
        
        # Domain age risk (brand new domains are highly suspicious)
        domain_age_days = features.get("domain_age_days")
        if domain_age_days is not None:
            if domain_age_days < 3:
                risk_score += 40
                logger.debug(f"Domain age risk: {domain_age_days} days < 3 -> +40")
            elif domain_age_days < 30:
                risk_score += 25
                logger.debug(f"Domain age risk: {domain_age_days} days < 30 -> +25")
        
        # Cap score at 100
        original_score = risk_score
        risk_score = min(risk_score, 100)
        if original_score > 100:
            logger.debug(f"Risk score capped from {original_score} to {risk_score}")
        
        # Determine prediction
        if risk_score < 30:
            prediction = "safe"
        elif risk_score < 70:
            prediction = "suspicious"
        else:
            prediction = "phishing"
            
        logger.debug(f"Final risk score: {risk_score}, prediction: {prediction}")
        
        return {
            "risk_score": risk_score,
            "prediction": prediction
        }
    except Exception as e:
        logger.error(f"Error calculating risk: {e}")
        # Return a safe default in case of error
        return {
            "risk_score": 0,
            "prediction": "safe"
        }