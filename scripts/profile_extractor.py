import sys
import os
import time
import numpy as np

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.normalizer import normalize_url
from app.core.extractor import extract_features, ngram_vectorizer, calculate_brand_spoofing

def profile():
    test_urls = [
        "https://www.google.com/search?q=trustguard",
        "http://secure-login-paypa1-update.com/signin?token=123",
        "https://www.xn--micrsft-90a.com/login",
        "http://www.bankofamerica-verify-acc.com/",
        "https://example.com"
    ]
    
    # Warmup
    for u in test_urls:
        normalized = normalize_url(u)
        extract_features(normalized)
        
    runs = 1000
    
    # Profile Levenshtein separately
    start_lev = time.perf_counter()
    for _ in range(runs):
        for u in test_urls:
            domain = normalize_url(u)["domain"]
            calculate_brand_spoofing(domain)
    time_lev = (time.perf_counter() - start_lev) * 1000 / (runs * len(test_urls))
    
    # Profile HashingVectorizer separately
    start_hash = time.perf_counter()
    for _ in range(runs):
        for u in test_urls:
            url = normalize_url(u)["url"]
            ngram_vectorizer.transform([url])
    time_hash = (time.perf_counter() - start_hash) * 1000 / (runs * len(test_urls))
    
    # Profile Full Extractor
    start_full = time.perf_counter()
    for _ in range(runs):
        for u in test_urls:
            normalized = normalize_url(u)
            extract_features(normalized)
    time_full = (time.perf_counter() - start_full) * 1000 / (runs * len(test_urls))
    
    print(f"--- Profiling Results (per URL) ---")
    print(f"Brand Levenshtein: {time_lev:.4f} ms")
    print(f"HashingVectorizer: {time_hash:.4f} ms")
    print(f"Full Extractor:    {time_full:.4f} ms")

if __name__ == "__main__":
    profile()
