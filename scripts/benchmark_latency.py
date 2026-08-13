import sys
import os
import time
import numpy as np

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.normalizer import normalize_url
from app.core.extractor import extract_features
from app.core.predictor import load_model, predict

def benchmark():
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
    
    # Warmup
    for u in test_urls:
        normalized = normalize_url(u)
        feats = extract_features(normalized)
        predict(feats)
        
    # Benchmark
    latencies = []
    for _ in range(200):
        for u in test_urls:
            start_time = time.perf_counter()
            normalized = normalize_url(u)
            feats = extract_features(normalized)
            res = predict(feats)
            end_time = time.perf_counter()
            
            latencies.append((end_time - start_time) * 1000) # ms
            
    latencies = np.array(latencies)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    avg = np.mean(latencies)
    
    print(f"--- Latency Benchmark ---")
    print(f"Total Runs: {len(latencies)}")
    print(f"Average: {avg:.3f} ms")
    print(f"p95:     {p95:.3f} ms")
    print(f"p99:     {p99:.3f} ms")
    
    if p95 < 2.0:
        print("SUCCESS: p95 latency is well under the 2.0ms SLA.")
    else:
        print("WARNING: p95 latency exceeded the 2.0ms SLA!")

if __name__ == "__main__":
    benchmark()
