from prometheus_client import Histogram, Counter
import time
from typing import Callable, Any
from functools import wraps

# --- Metrics Definitions ---

REQUEST_LATENCY = Histogram(
    "trustguard_request_latency_seconds",
    "Request latency in seconds",
    ["module", "stage"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0]
)

MODULE_REQUESTS = Counter(
    "trustguard_module_requests_total",
    "Total number of requests per module",
    ["module"]
)

THREATS_DETECTED = Counter(
    "trustguard_threats_detected_total",
    "Total threats detected by type and severity",
    ["threat_type", "severity", "model_version"]
)

PREDICTION_PROBABILITY = Histogram(
    "trustguard_prediction_probability",
    "Raw ML probability scores for drift monitoring",
    ["model_version"],
    buckets=[0.0, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0]
)

CANARY_LATENCY = Histogram(
    "trustguard_canary_latency_seconds",
    "Latency of the canary candidate model",
    ["version"],
    buckets=[0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.010, 0.015, 0.020]
)

CANARY_ERRORS = Counter(
    "trustguard_canary_errors_total",
    "Total errors thrown by the canary candidate model",
    ["version"]
)
def track_latency(module: str, stage: str = "full") -> Callable:
    """
    Decorator to track execution time of a function in the prometheus histogram.
    """
    def decorator(func: Callable) -> Callable:
        # Check if the function is async
        import asyncio
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                try:
                    return await func(*args, **kwargs)
                finally:
                    duration = time.perf_counter() - start_time
                    REQUEST_LATENCY.labels(module=module, stage=stage).observe(duration)
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    duration = time.perf_counter() - start_time
                    REQUEST_LATENCY.labels(module=module, stage=stage).observe(duration)
            return sync_wrapper
    return decorator
