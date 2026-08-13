import logging
import shap
import numpy as np
import traceback

# Set up logger
logger = logging.getLogger(__name__)

# Cache the SHAP explainer globally so we don't rebuild it on every request
_shap_explainer = None
_shap_feature_names = None

def _get_shap_explainer():
    """Lazily load and cache the SHAP explainer for the LightGBM model."""
    global _shap_explainer, _shap_feature_names
    if _shap_explainer is not None:
        return _shap_explainer, _shap_feature_names
        
    try:
        from app.core.predictor import _active_lgbm_pipeline
        if _active_lgbm_pipeline is None:
            return None, None
            
        calibrated_model = _active_lgbm_pipeline["model"]
        _shap_feature_names = _active_lgbm_pipeline["feature_names"]
        
        # Extract the base LightGBM model from CalibratedClassifierCV(FrozenEstimator(LGBMClassifier))
        lgbm_model = calibrated_model.calibrated_classifiers_[0].estimator.estimator
        _shap_explainer = shap.TreeExplainer(lgbm_model)
        
        return _shap_explainer, _shap_feature_names
    except Exception as e:
        logger.error(f"Failed to initialize SHAP explainer: {e}")
        return None, None

def _get_feature_description(feature_name: str, feature_value: float) -> str:
    """Translate raw feature names into human-readable descriptions."""
    if feature_name == "brand_spoof_risk" and feature_value > 0:
        return "High similarity to a targeted brand (potential typosquatting)"
    elif feature_name == "is_punycode" and feature_value > 0:
        return "Uses Punycode (xn--) to obscure the real domain"
    elif feature_name == "non_ascii_ratio" and feature_value > 0:
        return "Contains non-standard characters (potential homoglyph attack)"
    elif feature_name == "entropy" and feature_value > 4.0:
        return f"High randomness (entropy {feature_value:.1f}) typical of obfuscation"
    elif feature_name == "subdomain_count" and feature_value > 2:
        return f"Unusually high number of subdomains ({int(feature_value)})"
    elif feature_name == "suspicious_keywords" and feature_value > 0:
        return f"Contains {int(feature_value)} phishing-related keyword(s)"
    elif feature_name.startswith("ngram_") and feature_value > 0:
        return "Unusual structural character patterns detected in the URL"
    elif feature_name == "url_length" and feature_value > 75:
        return f"Suspiciously long URL length ({int(feature_value)} chars)"
    elif feature_name == "domain_length" and feature_value > 25:
        return f"Suspiciously long domain name ({int(feature_value)} chars)"
    return f"Suspicious signal from '{feature_name}'"

def explain(features: dict, is_blacklisted: bool = False, ml_score: float | None = None, vt_score: float | None = None) -> tuple[list[str], dict]:
    """Generate human-readable explanations using lazy SHAP computation."""
    reasons = []
    shap_dict = {}
    
    if is_blacklisted:
        reasons.append("URL was found in known threat intelligence blacklists (OpenPhish / URLHaus).")
        
    if vt_score is not None and vt_score > 0:
        reasons.append(f"VirusTotal Consensus: Multiple security vendors have flagged this URL as malicious (VT Score: {vt_score:.2f}).")
        
    if ml_score is not None and ml_score >= 0.3:
        reasons.append(f"Machine learning model calculated a {ml_score*100:.1f}% probability of phishing.")
        
        explainer, feature_names = _get_shap_explainer()
        if explainer and feature_names:
            try:
                # Construct exact feature vector
                X = np.array([[float(features.get(k, 0.0)) for k in feature_names]])
                shap_values = explainer.shap_values(X)[0] # Shape: (n_features,)
                
                # We want the features that pushed the prediction positively (towards phishing)
                # Sort by SHAP value descending
                top_indices = np.argsort(-shap_values)
                
                added_ngrams = False
                top_count = 0
                for idx in top_indices:
                    val = shap_values[idx]
                    if val <= 0.1: # Only care about significant positive contributions
                        break
                        
                    feat_name = feature_names[idx]
                    feat_val = X[0, idx]
                    
                    # Prevent listing multiple ngrams
                    if feat_name.startswith("ngram_"):
                        if added_ngrams:
                            continue
                        added_ngrams = True
                        
                    desc = _get_feature_description(feat_name, feat_val)
                    reasons.append(f"• {desc} (impact: {val:.2f})")
                    shap_dict[feat_name] = float(val)
                    
                    top_count += 1
                    if top_count >= 3: # Limit to top 3 reasons to keep UI clean
                        break
                        
            except Exception as e:
                logger.error(f"SHAP explanation failed: {traceback.format_exc()}")
                _fallback_rule_reasons(features, reasons)
        else:
            _fallback_rule_reasons(features, reasons)
            
    if not reasons:
        reasons.append("No suspicious traits detected.")
        
    return reasons, shap_dict

def _fallback_rule_reasons(features: dict, reasons: list[str]):
    """Fallback to old rule-based logic if SHAP is unavailable."""
    if features.get("brand_spoof_risk", 0) > 0:
        reasons.append("• High similarity to a targeted brand (potential typosquatting)")
    if features.get("is_punycode", 0) > 0:
        reasons.append("• Uses Punycode (xn--) to obscure the real domain")
    if features.get("suspicious_keywords", 0) > 0:
        reasons.append(f"• Contains {features['suspicious_keywords']} suspicious keyword(s)")
    if features.get("entropy", 0) > 4.5:
        reasons.append("• High character entropy suggesting obfuscation")