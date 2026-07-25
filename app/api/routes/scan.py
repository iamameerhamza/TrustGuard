from fastapi import APIRouter, Depends
from app.api.schemas import ScanRequest, ScanResponse
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features
from app.core.rules import calculate_risk
from app.core.db import log_scan
from app.core.predictor import predict
from app.core.cache import get_cached_result, set_cached_result
from app.core.threat_intel import check_blacklist
from app.core.explainer import explain
from app.core.rate_limiter import check_rate_limit
from app.modules.whois_checker import check_domain

router = APIRouter()

@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(check_rate_limit)])
def scan_url(request: ScanRequest):
    normalized = normalize_url(request.url)
    cached = get_cached_result(normalized["url"])
    if cached:
        return cached

    is_blacklisted = check_blacklist(request.url)
    features = extract_features(normalized)
    whois_result = check_domain(normalized["domain"])
    
    vt_score = None
    if is_blacklisted:
        risk_score = 100
        prediction = "phishing"
        ml_score = None
        ml_prediction = None
    else:
        ml_result = predict(features)
        ml_score = ml_result.get("ml_score")
        ml_prediction = ml_result.get("ml_prediction")
        
        effective_ml_score = ml_score if ml_score is not None else 0.5
        
        # New interim weight split: ML 0.58 + WHOIS 0.42
        fused_score = (effective_ml_score * 0.58) + (whois_result["score"] * 0.42)
        risk_score = int(fused_score * 100)
        
        if risk_score < 30:
            prediction = "safe"
        elif risk_score < 70:
            prediction = "suspicious"
        else:
            prediction = "phishing"
        
        if (ml_score is not None and ml_score >= 0.4) or risk_score >= 40:
            from app.core.virustotal import check_virustotal
            vt_result = check_virustotal(request.url)
            if vt_result:
                vt_score = vt_result.get("score")
                if vt_score is not None and vt_score > 0:
                    risk_score = 100
                    prediction = "phishing"
    
    reasons = explain(features, is_blacklisted, ml_score, vt_score)
    
    log_scan(
        "trustguard.db", request.url, risk_score, prediction,
        ml_score=ml_score, ml_prediction=ml_prediction,
        blacklisted=is_blacklisted, reasons=reasons
    )
    
    response = ScanResponse(
        **normalized, 
        features=features, 
        risk_score=risk_score, 
        prediction=prediction,
        ml_score=ml_score,
        ml_prediction=ml_prediction,
        vt_score=vt_score,
        blacklisted=is_blacklisted,
        reasons=reasons,
        whois={
            "age_days": whois_result["age_days"],
            "score":    whois_result["score"],
            "label":    whois_result["label"],
            "reason":   whois_result["reason"],
        }
    )
    
    set_cached_result(normalized["url"], response)
    return response
