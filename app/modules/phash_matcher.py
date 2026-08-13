import base64
import io
import json
import os
from typing import Any
from PIL import Image

try:
    import imagehash
    HAS_IMAGEHASH = True
except Exception:
    HAS_IMAGEHASH = False

try:
    import pytesseract
    HAS_TESSERACT = True
except Exception:
    HAS_TESSERACT = False

DEFAULT_REFERENCES = {
    "google": "a8f3d2c1b4e50977",
    "microsoft": "b7e4a1c3d9f20855",
    "paypal": "c5d8e2a1b3f70944",
    "apple": "d4a1c7e2b5f80366",
}

REF_PATH = os.getenv("TRUSTGUARD_PHASH_REFS", "data/phash_references.json")

def load_references() -> dict[str, str]:
    if os.path.exists(REF_PATH):
        with open(REF_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_REFERENCES

def hamming_distance(hash1: str, hash2: str) -> int:
    """Compute Hamming distance between two hex pHash strings (64-bit)."""
    if len(hash1) != len(hash2):
        m = max(len(hash1), len(hash2))
        hash1 = hash1.zfill(m)
        hash2 = hash2.zfill(m)
    int1 = int(hash1, 16)
    int2 = int(hash2, 16)
    x = int1 ^ int2
    return bin(x).count('1')

def compute_phash(image: Image.Image) -> str:
    if not HAS_IMAGEHASH:
        raise RuntimeError("imagehash is required. Install with: pip install imagehash")
    phash = imagehash.phash(image)
    return str(phash)

def detect_brand_text(image: Image.Image) -> str:
    """Extract text using Tesseract OCR to find brand mentions."""
    if not HAS_TESSERACT:
        return ""
    try:
        text = pytesseract.image_to_string(image).lower()
        for brand in ["microsoft", "google", "paypal", "apple", "amazon"]:
            if brand in text:
                return brand
    except Exception:
        # Fails gracefully if tesseract executable is not in PATH
        pass
    return ""

def match_brand(phash_hex: str, max_distance: int = 12) -> dict[str, Any] | None:
    refs = load_references()
    best_brand = None
    best_score = -1.0
    best_dist = 999
    
    for brand, ref_hash in refs.items():
        dist = hamming_distance(phash_hex, ref_hash)
        similarity = 1.0 - (dist / 64.0)
        if dist <= max_distance and similarity > best_score:
            best_score = similarity
            best_brand = brand
            best_dist = dist
    
    if best_brand:
        return {
            "brand": best_brand,
            "similarity": round(best_score, 4),
            "hamming_distance": best_dist
        }
    return None

def analyze_visual(b64_image: str, target_brand: str | None = None) -> dict[str, Any]:
    if "," in b64_image:
        b64_image = b64_image.split(",", 1)[1]
    image_bytes = base64.b64decode(b64_image)
    image = Image.open(io.BytesIO(image_bytes))
    
    phash = compute_phash(image)
    ocr_brand = detect_brand_text(image)
    
    match = None
    if target_brand:
        refs = load_references()
        if target_brand.lower() in refs:
            dist = hamming_distance(phash, refs[target_brand.lower()])
            sim = 1.0 - (dist / 64.0)
            match = {"brand": target_brand.lower(), "similarity": round(sim, 4), "hamming_distance": dist}
    else:
        match = match_brand(phash)
    
    is_spoof = False
    risk_score = 0
    
    # Base pHash Risk Score
    if match:
        if match["similarity"] > 0.85:
            is_spoof = True
            risk_score = min(int((match["similarity"] - 0.85) / 0.15 * 100), 100)
            
    # OCR Context Fusion
    if ocr_brand:
        # If we found a highly sensitive brand via OCR...
        if target_brand and ocr_brand != target_brand.lower():
            # e.g., We expect 'internal-site' but OCR says 'Microsoft' -> high risk
            is_spoof = True
            risk_score = max(risk_score, 85)
        elif not match:
            # We see 'Microsoft' text but pHash doesn't match a known microsoft reference?
            # Could be a new spoof template that evades our pHash signatures!
            is_spoof = True
            risk_score = max(risk_score, 75)
            # Make a synthetic match result so the frontend knows we matched the brand via OCR
            match = {"brand": ocr_brand, "similarity": 0.0, "hamming_distance": 64, "ocr_detected": True}
    
    return {
        "phash_signature": phash,
        "matched_brand": match["brand"] if match else None,
        "similarity_score": match["similarity"] if match else 0.0,
        "is_spoof": is_spoof,
        "risk_score": risk_score
    }
