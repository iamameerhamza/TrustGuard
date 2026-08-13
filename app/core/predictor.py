import os
import joblib
import logging
import random
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set up logger
logger = logging.getLogger(__name__)

_active_lgbm_pipeline = None
_active_version = None
_active_threshold = 0.5

_candidate_lgbm_pipeline = None
_candidate_version = None
_candidate_threshold = 0.5

_rf_model = None
_observer = None

CANARY_TRAFFIC_PCT = float(os.getenv("CANARY_TRAFFIC_PCT", "0.05"))

def _load_model_version(models_dir: str, version_file: str):
    version_path = os.path.join(models_dir, version_file)
    if not os.path.exists(version_path):
        return None, None, 0.5
        
    try:
        with open(version_path, "r") as f:
            version = f.read().strip()
            
        version_dir = os.path.join(models_dir, version)
        lgbm_path = os.path.join(version_dir, "lgbm_calibrated.joblib")
        thresh_path = os.path.join(version_dir, "optimal_threshold.txt")
        
        if not os.path.exists(lgbm_path):
            logger.error(f"Version pointer {version_file} points to {version}, but {lgbm_path} is missing.")
            return None, version, 0.5
            
        pipeline = joblib.load(lgbm_path)
        
        threshold = 0.5
        if os.path.exists(thresh_path):
            with open(thresh_path, "r") as f:
                threshold = float(f.read().strip())
                
        return pipeline, version, threshold
    except Exception as e:
        logger.error(f"Failed to load model from {version_file}: {e}")
        return None, None, 0.5

class ModelReloadHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global _active_lgbm_pipeline, _active_version, _active_threshold
        global _candidate_lgbm_pipeline, _candidate_version, _candidate_threshold
        global _rf_model
        
        if event.src_path.endswith("active_version.txt"):
            logger.info("active_version.txt modified! Hot-reloading active model...")
            models_dir = os.path.dirname(event.src_path)
            pipeline, version, threshold = _load_model_version(models_dir, "active_version.txt")
            if pipeline:
                _active_lgbm_pipeline = pipeline
                _active_version = version
                _active_threshold = threshold
                logger.info(f"Active model hot-reloaded successfully. Version: {version}")
                
        elif event.src_path.endswith("candidate_version.txt"):
            logger.info("candidate_version.txt modified! Hot-reloading candidate model...")
            models_dir = os.path.dirname(event.src_path)
            pipeline, version, threshold = _load_model_version(models_dir, "candidate_version.txt")
            if pipeline:
                _candidate_lgbm_pipeline = pipeline
                _candidate_version = version
                _candidate_threshold = threshold
                logger.info(f"Candidate model hot-reloaded successfully. Version: {version}")
                
        elif event.src_path.endswith("phishing_rf.joblib"):
            logger.info("RandomForest model file modified! Hot-reloading...")
            try:
                _rf_model = joblib.load(event.src_path)
                logger.info("RandomForest model hot-reloaded successfully.")
            except Exception as e:
                logger.error(f"Failed to reload RF model: {e}")

def load_model(models_dir: str = "models") -> bool:
    """Load both ML models (LightGBM primary via version pointer, RF fallback) and start file watcher.
    
    Args:
        models_dir: Directory containing the joblib model files and pointers
        
    Returns:
        bool: True if at least one model loaded successfully, False otherwise
    """
    global _active_lgbm_pipeline, _active_version, _active_threshold
    global _candidate_lgbm_pipeline, _candidate_version, _candidate_threshold
    global _rf_model, _observer
    
    _active_lgbm_pipeline, _active_version, _active_threshold = _load_model_version(models_dir, "active_version.txt")
    _candidate_lgbm_pipeline, _candidate_version, _candidate_threshold = _load_model_version(models_dir, "candidate_version.txt")
    
    rf_path = os.path.join(models_dir, "phishing_rf.joblib")
    
    loaded_any = False
    
    if _active_lgbm_pipeline:
        logger.info(f"--- ML Engine Ready ---")
        logger.info(f"Active Model: LightGBM (Version: {_active_version})")
        logger.info(f"Operating Threshold: {_active_threshold:.4f}")
        logger.info(f"-----------------------")
        loaded_any = True
        
    if _candidate_lgbm_pipeline:
        logger.info(f"--- Canary Engine Ready ---")
        logger.info(f"Candidate Model: LightGBM (Version: {_candidate_version})")
        logger.info(f"Operating Threshold: {_candidate_threshold:.4f}")
        logger.info(f"Traffic Routing: {CANARY_TRAFFIC_PCT*100}%")
        logger.info(f"-----------------------")
        
    if os.path.exists(rf_path):
        try:
            _rf_model = joblib.load(rf_path)
            logger.info(f"RandomForest fallback model loaded from {rf_path}")
            loaded_any = True
        except Exception as e:
            logger.error(f"Failed to load RandomForest from {rf_path}: {e}")
            _rf_model = None
            
    if loaded_any and _observer is None:
        event_handler = ModelReloadHandler()
        _observer = Observer()
        _observer.schedule(event_handler, path=os.path.abspath(models_dir), recursive=False)
        _observer.start()
        logger.info("Model watchdog observer started.")
        
    if not loaded_any:
        logger.warning("No models could be loaded. ML predictions will be disabled.")
        
    return loaded_any

def stop_observer():
    """Stop the model file watcher observer."""
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
        _observer = None
        logger.info("Model watchdog observer stopped.")

from app.core.telemetry import track_latency, PREDICTION_PROBABILITY, CANARY_LATENCY, CANARY_ERRORS
import time

@track_latency(module="url", stage="inference")
def predict(features: dict) -> dict:
    """Make a prediction using LightGBM (primary or candidate) or Random Forest (fallback)."""
    global _active_lgbm_pipeline, _active_version, _active_threshold
    global _candidate_lgbm_pipeline, _candidate_version, _candidate_threshold
    global _rf_model
    
    # Probabilistic routing
    use_canary = False
    if _candidate_lgbm_pipeline is not None and random.random() < CANARY_TRAFFIC_PCT:
        use_canary = True
        
    target_pipeline = _candidate_lgbm_pipeline if use_canary else _active_lgbm_pipeline
    target_version = _candidate_version if use_canary else _active_version
    target_threshold = _candidate_threshold if use_canary else _active_threshold
    
    # 1. Try LightGBM
    if target_pipeline is not None:
        start_t = time.perf_counter()
        try:
            model = target_pipeline["model"]
            feature_names = target_pipeline["feature_names"]
            
            # Construct feature vector in exact order
            X_lgbm = [[float(features.get(k, 0.0)) for k in feature_names]]
            
            proba = model.predict_proba(X_lgbm)[0]
            ml_score = float(proba[1])
            ml_prediction = "phishing" if ml_score >= target_threshold else "safe"
            
            # Record drift and ops metrics
            PREDICTION_PROBABILITY.labels(model_version=target_version).observe(ml_score)
            if use_canary:
                CANARY_LATENCY.labels(version=target_version).observe(time.perf_counter() - start_t)
            
            logger_prefix = "[CANARY]" if use_canary else "[ACTIVE]"
            logger.debug(f"{logger_prefix} LightGBM prediction: {ml_prediction} (score: {ml_score:.4f} against thresh {target_threshold})")
            
            return {
                "ml_score": ml_score, 
                "ml_prediction": ml_prediction, 
                "model_used": "lightgbm",
                "model_version": target_version,
                "is_canary": use_canary
            }
        except Exception as e:
            if use_canary:
                CANARY_ERRORS.labels(version=target_version).inc()
            logger.error(f"LightGBM prediction error, falling back to RF: {e}")
            
    # 2. Try Random Forest Fallback
    if _rf_model is not None:
        try:
            X_rf = [[
                float(features.get("url_length", 0)),
                float(features.get("domain_length", 0)),
                float(features.get("subdomain_count", 0)),
                1.0 if features.get("has_special_chars") else 0.0,
                float(features.get("entropy", 0.0)),
                float(features.get("suspicious_keywords", 0))
            ]]
            proba = _rf_model.predict_proba(X_rf)[0]
            ml_score = float(proba[1])
            ml_prediction = "phishing" if ml_score >= 0.5 else "safe" # RF keeps its original 0.5 threshold
            logger.debug(f"RF Fallback prediction: {ml_prediction} (score: {ml_score:.4f})")
            return {
                "ml_score": ml_score, 
                "ml_prediction": ml_prediction, 
                "model_used": "random_forest",
                "model_version": "fallback_rf",
                "is_canary": False
            }
        except Exception as e:
            logger.error(f"RF Fallback prediction error: {e}")
            
    logger.warning("All models failed or none loaded, returning None predictions")
    return {
        "ml_score": None, 
        "ml_prediction": None, 
        "model_used": None,
        "model_version": None,
        "is_canary": False
    }