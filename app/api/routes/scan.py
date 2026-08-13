import os
from fastapi import APIRouter, Depends, HTTPException, Request
from app.api.schemas import ScanRequest, ScanResponse
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features
from app.core.rules import calculate_risk
from app.core.db import log_scan
from app.core.predictor import predict
from app.core.cache import get_cached_result, set_cached_result
from app.core.threat_intel import check_blacklist
from app.core.explainer import explain
from app.core.rate_limit import limiter
from app.modules.whois_checker import check_domain

router = APIRouter()
DB_PATH = os.getenv("TRUSTGUARD_DB", "trustguard.db")

@router.post("/scan", response_model=ScanResponse)
@limiter.limit("100/minute")
async def scan_url(request: Request, payload: ScanRequest):
    # ── 1. Normalize & cache check ──
    try:
        normalized = normalize_url(payload.url)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {exc}")

    cached = await get_cached_result(normalized["url"])
    if cached:
        return cached

    # ── 2. Blacklist short-circuit (skip heavy compute) ──
    is_blacklisted = check_blacklist(payload.url)
    if is_blacklisted:
        reasons, shap_values = explain({}, is_blacklisted=True, ml_score=None, vt_score=None)
        response = ScanResponse(
            **normalized,
            features={},
            risk_score=100,
            prediction="phishing",
            ml_score=None,
            ml_prediction=None,
            vt_score=None,
            blacklisted=True,
            reasons=reasons,
            whois={"age_days": None, "score": 0, "label": "blacklisted", "reason": "Domain found in threat intel feed"},
        )
        log_scan(DB_PATH, payload.url, 100, "phishing", ml_score=None, ml_prediction=None, blacklisted=True, reasons=response.reasons, shap_values=shap_values)
        await set_cached_result(normalized["url"], response)
        
        from app.core.telemetry import MODULE_REQUESTS, THREATS_DETECTED
        MODULE_REQUESTS.labels(module="url").inc()
        THREATS_DETECTED.labels(threat_type="blacklist", severity="phishing", model_version="none").inc()
        
        return response

    # ── 3. Feature extraction & WHOIS (parallel-ready structure) ──
    try:
        features = extract_features(normalized)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {exc}")

    try:
        whois_result = await check_domain(normalized["domain"])
    except Exception:
        # WHOIS is advisory; degrade gracefully
        whois_result = {"age_days": None, "score": 0.5, "label": "unknown", "reason": "WHOIS lookup failed"}

    # ── 4. ML / Rule hybrid scoring ──
    try:
        ml_result = predict(features)
        ml_score = ml_result.get("ml_score")
        ml_prediction = ml_result.get("ml_prediction")
    except Exception:
        ml_score = None
        ml_prediction = None

    if ml_score is None:
        rule_result = calculate_risk(features)
        effective_ml_score = rule_result["risk_score"] / 100.0
    else:
        effective_ml_score = ml_score

    # BUG FIX: Normalize WHOIS score to 0–1 scale before fusion
    raw_whois_score = whois_result.get("score", 0)
    whois_score_norm = raw_whois_score / 100.0 if raw_whois_score > 1 else raw_whois_score

    # ── 5. VirusTotal lookup (Tranco Allowlist Gate) ──
    vt_score = None
    vt_signal = None
    
    import tldextract
    ext = tldextract.extract(payload.url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    trusted_domains = getattr(request.app.state, "trusted_domains", set())
    
    if registered_domain not in trusted_domains:
        try:
            vt_client = request.app.state.vt_client
            vt_signal = await vt_client.scan_url(payload.url)
            from modules.intake.virustotal_client import VTSignalState
            
            if vt_signal.state == VTSignalState.SCORED and vt_signal.score is not None:
                vt_score = vt_signal.score / 100.0
            elif vt_signal.state == VTSignalState.INSUFFICIENT_COVERAGE:
                import logging
                logging.getLogger(__name__).warning(f"VT returned INSUFFICIENT_COVERAGE for {payload.url} (only {vt_signal.engines_scored} engines)")
                vt_score = None
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"VT scan failed: {e}")
            vt_score = None

    # ── 6. Final Risk Score Fusion ──
    W_ML = float(os.getenv("WEIGHT_ML", "0.58"))
    W_WH = float(os.getenv("WEIGHT_WHOIS", "0.42"))
    
    # Base Score (ML + WHOIS)
    total_w = W_ML + W_WH
    base_score = ((effective_ml_score * W_ML) + (whois_score_norm * W_WH)) / total_w
    risk_score = min(int(base_score * 100), 100)
    
    # Phase 5: VT Hard Floor (No Dilution)
    VT_SUSPICIOUS_DETECTION_PCT = 5  # ~3 engines out of 70 -> force Suspicious
    VT_CRITICAL_DETECTION_PCT = 15   # ~10 engines out of 70 -> force Phishing
    
    if vt_score is not None:
        vt_risk = int(vt_score * 100)
        if vt_risk >= VT_SUSPICIOUS_DETECTION_PCT:
            risk_score = max(risk_score, 50)
        if vt_risk >= VT_CRITICAL_DETECTION_PCT:
            risk_score = max(risk_score, 75)
            
    # ── Phase 5: Hard Overrides (Defense in Depth) ──
    # 1. Brand Spoof Override: LightGBM natively buries this clean signal under n-grams.
    if features.get("brand_spoof_risk", 0) > 0:
        risk_score = max(risk_score, 85)
        
    # 2. Suspicious Payload Override:
    from urllib.parse import urlparse
    parsed_url = urlparse(payload.url)
    suspicious_exts = (".exe", ".inf", ".cur", ".msi", ".scr", ".vbs", ".bat")
    
    clean_path = parsed_url.path.strip().rstrip('.')
    clean_query = parsed_url.query.strip().rstrip('.')
    
    if clean_path.lower().endswith(suspicious_exts) or clean_query.lower().endswith(suspicious_exts):
        risk_score = max(risk_score, 75)

    if risk_score < 30:
        prediction = "safe"
    elif risk_score < 70:
        prediction = "suspicious"
    else:
        prediction = "phishing"

    from app.core.telemetry import MODULE_REQUESTS, THREATS_DETECTED

    # ── 6. Explain, persist, cache ──
    reasons, shap_values = explain(features, is_blacklisted=False, ml_score=ml_score, vt_score=vt_score)

    log_scan(
        DB_PATH, payload.url, risk_score, prediction,
        ml_score=ml_score, ml_prediction=ml_prediction,
        blacklisted=False, reasons=reasons, shap_values=shap_values
    )
    
    MODULE_REQUESTS.labels(module="url").inc()
    if prediction != "safe":
        THREATS_DETECTED.labels(threat_type="phishing", severity=prediction, model_version="lgbm_calibrated").inc()

    response = ScanResponse(
        **normalized,
        features=features,
        risk_score=risk_score,
        prediction=prediction,
        ml_score=ml_score,
        ml_prediction=ml_prediction,
        vt_score=vt_score,
        blacklisted=False,
        reasons=reasons,
        whois={
            "age_days": whois_result.get("age_days"),
            "score": raw_whois_score,
            "label": whois_result.get("label"),
            "reason": whois_result.get("reason"),
        }
    )

    await set_cached_result(normalized["url"], response)
    return response
