import sys
import os
import time
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.normalizer import normalize_url
from app.core.extractor import extract_features
from app.core.predictor import load_model, predict

def profile():
    if not load_model("models"):
        print("Failed to load models.")
        return
        
    test_urls = [
        "https://www.google.com/search?q=trustguard",
        "http://secure-login-paypa1-update.com/signin?token=123",
        "https://www.xn--micrsft-90a.com/login",
        "http://www.bankofamerica-verify-acc.com/",
        "https://example.com"
    ]
    
    feats_list = [extract_features(normalize_url(u)) for u in test_urls]
    
    # Warmup
    for f in feats_list:
        predict(f)
        
    runs = 1000
    start = time.perf_counter()
    for _ in range(runs):
        for f in feats_list:
            predict(f)
    time_pred = (time.perf_counter() - start) * 1000 / (runs * len(test_urls))
    
    print(f"--- Profiling Results (per URL) ---")
    print(f"Predict (LightGBM): {time_pred:.4f} ms")

if __name__ == "__main__":
    profile()
