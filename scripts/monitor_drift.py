import os
import sys
import json
import httpx
import logging
import numpy as np
from scipy.stats import entropy
from prometheus_client.parser import text_string_to_metric_families

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def monitor_drift(metrics_url: str = "http://localhost:8000/metrics", models_dir: str = "models"):
    # 1. Get active model version
    active_pointer = os.path.join(models_dir, "active_version.txt")
    if not os.path.exists(active_pointer):
        logger.error("No active_version.txt found.")
        return
        
    with open(active_pointer, "r") as f:
        active_version = f.read().strip()
        
    # 2. Load baseline validation distribution
    dist_path = os.path.join(models_dir, active_version, "val_distribution.json")
    if not os.path.exists(dist_path):
        logger.error(f"No baseline distribution found at {dist_path}")
        return
        
    with open(dist_path, "r") as f:
        baseline_data = json.load(f)
        
    baseline_probs = np.array(baseline_data["probabilities"])
    # Ensure no exact zeros for KL Divergence
    baseline_probs = np.where(baseline_probs == 0, 1e-10, baseline_probs)
    
    # 3. Query Prometheus for live distribution
    try:
        response = httpx.get(metrics_url)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to fetch metrics from {metrics_url}: {e}")
        return
        
    metrics_text = response.text
    families = text_string_to_metric_families(metrics_text)
    
    live_counts = np.zeros(20) # 20 bins
    total_live_reqs = 0
    
    # Bins align with [0.0, 0.05, 0.1 ... 1.0]
    bucket_map = {
        "0.05": 0, "0.1": 1, "0.15": 2, "0.2": 3, "0.25": 4, "0.3": 5, "0.35": 6, "0.4": 7, 
        "0.45": 8, "0.5": 9, "0.55": 10, "0.6": 11, "0.65": 12, "0.7": 13, "0.75": 14, 
        "0.8": 15, "0.85": 16, "0.9": 17, "0.95": 18, "1.0": 19
    }
    
    for family in families:
        if family.name == "trustguard_prediction_probability":
            for sample in family.samples:
                if sample.name == "trustguard_prediction_probability_bucket":
                    model_ver = sample.labels.get("model_version")
                    le = sample.labels.get("le")
                    
                    if model_ver == active_version and le in bucket_map:
                        idx = bucket_map[le]
                        live_counts[idx] = sample.value
                        
    # Prometheus buckets are cumulative, we need to decumulate them to get raw counts per bin
    decumulated_counts = np.zeros(20)
    prev_count = 0
    for i in range(20):
        decumulated_counts[i] = live_counts[i] - prev_count
        prev_count = live_counts[i]
        
    total_live_reqs = np.sum(decumulated_counts)
    
    if total_live_reqs < 100:
        logger.info(f"Insufficient live requests ({total_live_reqs}) to calculate meaningful drift for version {active_version}.")
        return
        
    live_probs = decumulated_counts / total_live_reqs
    live_probs = np.where(live_probs == 0, 1e-10, live_probs)
    
    # 4. Calculate KL Divergence
    kl_div = entropy(live_probs, baseline_probs)
    
    logger.info(f"--- Drift Monitoring for {active_version} ---")
    logger.info(f"Requests observed: {int(total_live_reqs)}")
    logger.info(f"KL Divergence vs Baseline: {kl_div:.4f}")
    
    if kl_div > 0.5:
        logger.warning(f"HIGH DRIFT DETECTED (KL > 0.5). Model predictions have shifted significantly from validation distribution.")
    else:
        logger.info(f"Drift is within normal tolerances (KL <= 0.5).")

if __name__ == "__main__":
    monitor_drift()
