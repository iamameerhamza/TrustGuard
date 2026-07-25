import os
import joblib
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set up logger
logger = logging.getLogger(__name__)

_model = None
_observer = None

class ModelReloadHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("phishing_rf.joblib"):
            logger.info("Model file modified! Hot-reloading...")
            global _model
            try:
                _model = joblib.load(event.src_path)
                logger.info("Model hot-reloaded successfully.")
            except FileNotFoundError:
                logger.error(f"Model file not found: {event.src_path}")
            except Exception as e:
                logger.error(f"Failed to reload model: {e}")

def load_model(model_path: str = "models/phishing_rf.joblib") -> bool:
    """Load the ML model and start file watcher for hot-reloading.
    
    Args:
        model_path: Path to the joblib model file
        
    Returns:
        bool: True if model loaded successfully, False otherwise
    """
    global _model, _observer
    if os.path.exists(model_path):
        try:
            _model = joblib.load(model_path)
            logger.info(f"Model loaded successfully from {model_path}")
            
            if _observer is None:
                event_handler = ModelReloadHandler()
                _observer = Observer()
                model_dir = os.path.dirname(os.path.abspath(model_path))
                # Start monitoring the models directory
                _observer.schedule(event_handler, path=model_dir, recursive=False)
                _observer.start()
                logger.info("Model watchdog observer started.")
            return True
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}: {e}")
            _model = None
            return False
    else:
        logger.warning(f"Model file not found at {model_path}. ML predictions will be disabled.")
        return False

def stop_observer():
    """Stop the model file watcher observer."""
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
        _observer = None
        logger.info("Model watchdog observer stopped.")

def predict(features: dict) -> dict:
    """Make a prediction using the loaded ML model.
    
    Args:
        features: Dictionary of features for prediction
        
    Returns:
        Dictionary containing ml_score and ml_prediction
    """
    if _model is None:
        logger.warning("Model not loaded, returning None predictions")
        return {"ml_score": None, "ml_prediction": None}
    
    # Feature order must match training: url_length, domain_length, subdomain_count, has_special_chars, entropy, suspicious_keywords
    X = [[
        float(features.get("url_length", 0)),
        float(features.get("domain_length", 0)),
        float(features.get("subdomain_count", 0)),
        1.0 if features.get("has_special_chars") else 0.0,
        float(features.get("entropy", 0.0)),
        float(features.get("suspicious_keywords", 0))
    ]]
    
    try:
        proba = _model.predict_proba(X)[0]
        # proba[1] is the probability of class 1 (phishing)
        ml_score = float(proba[1])
        ml_prediction = "phishing" if ml_score >= 0.5 else "safe"
        logger.debug(f"ML prediction: {ml_prediction} (score: {ml_score:.4f})")
        return {"ml_score": ml_score, "ml_prediction": ml_prediction}
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return {"ml_score": None, "ml_prediction": None}