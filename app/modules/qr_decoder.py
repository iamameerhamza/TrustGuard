import base64
import io
import json
import os
from typing import Any
from urllib.parse import urljoin
from PIL import Image

try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except Exception:
    HAS_CV2 = False

import httpx
from app.api.schemas import QrScanResponse

def decode_qr_from_base64(b64_image: str) -> str | None:
    if not HAS_CV2:
        raise RuntimeError("OpenCV is required for QR decoding. Install with: pip install opencv-python-headless")
    if "," in b64_image:
        b64_image = b64_image.split(",", 1)[1]
    image_bytes = base64.b64decode(b64_image)
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    arr = np.array(image)
    arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(arr)
    return data if data else None

def follow_redirects(url: str, max_hops: int = 5, timeout: int = 10) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = url
    with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": "TrustGuard-Scanner/2.0"}) as client:
        for _ in range(max_hops):
            if current in seen:
                chain.append({"url": current, "status": "loop", "type": "error"})
                break
            seen.add(current)
            try:
                resp = client.head(current)
                if resp.status_code in (301, 302, 307, 308):
                    chain.append({"url": current, "status": resp.status_code, "type": "redirect"})
                    location = resp.headers.get("Location")
                    if not location:
                        break
                    current = urljoin(current, location)
                else:
                    chain.append({"url": current, "status": resp.status_code, "type": "final"})
                    break
            except Exception as exc:
                chain.append({"url": current, "status": str(exc), "type": "error"})
                break
    return chain

def load_qr_risk_matrix() -> dict[str, Any]:
    path = os.getenv("TRUSTGUARD_QR_MATRIX", "data/qr_risk_matrix.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def analyze_non_http_payload(payload: str) -> QrScanResponse:
    matrix = load_qr_risk_matrix()
    payload_type = "unknown"
    upper_payload = payload.upper()
    
    if upper_payload.startswith("WIFI:"):
        payload_type = "WIFI"
    elif upper_payload.startswith("SMSTO:"):
        payload_type = "SMSTO"
    elif upper_payload.startswith("MATMSG:"):
        payload_type = "MATMSG"
    elif upper_payload.startswith("GEO:"):
        payload_type = "geo"
    elif upper_payload.startswith("TEL:"):
        payload_type = "tel"
    elif upper_payload.startswith("BEGIN:VCARD"):
        payload_type = "vCard"
    elif upper_payload.startswith("BITCOIN:"):
        payload_type = "bitcoin"

    risk_info = matrix.get(payload_type, matrix.get("unknown", {"risk_score": 50, "description": "Unknown"}))
    risk_score = risk_info.get("risk_score", 50)
    
    # Increase risk if a vcard contains a URL secretly embedded
    if payload_type == "vCard" and ("http://" in payload.lower() or "https://" in payload.lower()):
        risk_score = max(risk_score, 65)

    prediction = "safe" if risk_score < 30 else "suspicious" if risk_score < 70 else "malicious"
    
    return QrScanResponse(
        decoded_url=payload,
        is_malicious=prediction == "malicious",
        risk_score=risk_score,
        redirect_chain=[],
        final_url=None,
        safety_report={
            "payload_type": payload_type,
            "description": risk_info.get("description", ""),
            "prediction": prediction
        }
    )

def analyze_qr_target(decoded_url: str) -> QrScanResponse:
    if not decoded_url.startswith(("http://", "https://")):
        return analyze_non_http_payload(decoded_url)

    from app.core.threat_intel import check_blacklist
    from app.core.normalizer import normalize_url
    from app.core.extractor import extract_features
    from app.core.rules import calculate_risk
    from app.modules.whois_checker import check_domain

    is_blacklisted = check_blacklist(decoded_url)
    redirect_chain = follow_redirects(decoded_url)
    final_url = redirect_chain[-1]["url"] if redirect_chain else decoded_url

    if is_blacklisted:
        return QrScanResponse(
            decoded_url=decoded_url,
            is_malicious=True,
            risk_score=100,
            redirect_chain=[h["url"] for h in redirect_chain],
            final_url=final_url,
            safety_report={"reason": "Domain found in threat intelligence blacklist", "prediction": "phishing"}
        )

    try:
        normalized = normalize_url(decoded_url)
        features = extract_features(normalized)
        rule_result = calculate_risk(features)
        whois_result = check_domain(normalized["domain"])

        risk_score = rule_result["risk_score"]
        raw_whois = whois_result.get("score", 0)
        whois_norm = raw_whois / 100.0 if raw_whois > 1 else raw_whois
        if whois_norm > 0.7:
            risk_score = max(risk_score, 85)

        prediction = "safe" if risk_score < 30 else "suspicious" if risk_score < 70 else "phishing"
    except Exception:
        risk_score = 50
        prediction = "unknown"
        features = {}
        whois_result = {}

    return QrScanResponse(
        decoded_url=decoded_url,
        is_malicious=prediction == "phishing",
        risk_score=risk_score,
        redirect_chain=[h["url"] for h in redirect_chain],
        final_url=final_url,
        safety_report={"features": features, "prediction": prediction, "whois": whois_result}
    )
