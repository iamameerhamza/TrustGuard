import os
import sys
import httpx
import logging
from prometheus_client.parser import text_string_to_metric_families

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def evaluate_canary(metrics_url: str = "http://localhost:8000/metrics"):
    canary_min_reqs = int(os.getenv("CANARY_MIN_REQUESTS", "1000"))
    
    try:
        response = httpx.get(metrics_url)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to fetch metrics from {metrics_url}: {e}")
        return
        
    metrics_text = response.text
    families = text_string_to_metric_families(metrics_text)
    
    canary_count = 0
    canary_sum = 0.0
    canary_errors = 0
    canary_version = None
    
    for family in families:
        if family.name == "trustguard_canary_latency_seconds":
            for sample in family.samples:
                if sample.name == "trustguard_canary_latency_seconds_count":
                    canary_count = sample.value
                    canary_version = sample.labels.get("version")
                elif sample.name == "trustguard_canary_latency_seconds_sum":
                    canary_sum = sample.value
        elif family.name == "trustguard_canary_errors_total":
            for sample in family.samples:
                canary_errors = sample.value
                
    if not canary_version:
        logger.warning("No canary metrics found in Prometheus payload. Is a candidate model deployed?")
        return
        
    logger.info(f"--- Evaluating Canary Version: {canary_version} ---")
    logger.info(f"Requests observed: {canary_count} / {canary_min_reqs} required")
    
    if canary_count < canary_min_reqs:
        logger.info("Decision: HOLD. Insufficient sample size to evaluate safely.")
        return
        
    avg_latency = (canary_sum / canary_count) if canary_count > 0 else 0
    error_rate = (canary_errors / canary_count) if canary_count > 0 else 0
    
    logger.info(f"Average Latency: {avg_latency*1000:.2f}ms")
    logger.info(f"Error Rate: {error_rate*100:.2f}%")
    
    # SLA Check
    passed = True
    if avg_latency > 0.0035: # 3.5ms SLA
        logger.error("SLA Violation: Average latency exceeds 3.5ms")
        passed = False
        
    if error_rate > 0.001: # 0.1% error rate limit
        logger.error("SLA Violation: Error rate exceeds 0.1%")
        passed = False
        
    if passed:
        logger.info("Decision: PASS. The canary model meets operational SLAs.")
        logger.info(f"To manually promote, run: os.replace('models/candidate_version.tmp', 'models/active_version.txt')")
    else:
        logger.error("Decision: FAIL. The canary model violates operational SLAs and should be rolled back.")

if __name__ == "__main__":
    evaluate_canary()
