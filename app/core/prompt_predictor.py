import os
import logging
import random
import asyncio
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

# Note: No PyTorch dependency at inference time!
import onnxruntime as ort
import numpy as np
from transformers import PreTrainedTokenizerFast

_active_ort_session = None
_active_version = None

_candidate_ort_session = None
_candidate_version = None

_tokenizer = None
_observer = None

CANARY_TRAFFIC_PCT = float(os.getenv("CANARY_TRAFFIC_PCT", "0.05"))

def _load_prompt_model_version(models_dir: str, version_file: str):
    version_path = os.path.join(models_dir, version_file)
    if not os.path.exists(version_path):
        return None, None
        
    try:
        with open(version_path, "r") as f:
            version = f.read().strip()
            
        model_dir = os.path.join(models_dir, version)
        onnx_path = os.path.join(model_dir, "prompt_model_int8.onnx")
        if not os.path.exists(onnx_path):
            onnx_path = os.path.join(model_dir, "prompt_model.onnx")
        
        if not os.path.exists(onnx_path):
            logger.error(f"Version pointer {version_file} points to {version}, but {onnx_path} is missing.")
            return None, version
            
        session = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
        return session, version
    except Exception as e:
        logger.error(f"Failed to load prompt model from {version_file}: {e}")
        return None, None

class PromptModelReloadHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global _active_ort_session, _active_version
        global _candidate_ort_session, _candidate_version
        
        if event.src_path.endswith("prompt_active_version.txt"):
            logger.info("prompt_active_version.txt modified! Hot-reloading active ONNX model...")
            models_dir = os.path.dirname(event.src_path)
            session, version = _load_prompt_model_version(models_dir, "prompt_active_version.txt")
            if session:
                _active_ort_session = session
                _active_version = version
                logger.info(f"Active Prompt ONNX model hot-reloaded successfully. Version: {version}")
                
        elif event.src_path.endswith("prompt_candidate_version.txt"):
            logger.info("prompt_candidate_version.txt modified! Hot-reloading candidate ONNX model...")
            models_dir = os.path.dirname(event.src_path)
            session, version = _load_prompt_model_version(models_dir, "prompt_candidate_version.txt")
            if session:
                _candidate_ort_session = session
                _candidate_version = version
                logger.info(f"Candidate Prompt ONNX model hot-reloaded successfully. Version: {version}")

def load_prompt_model(models_dir: str = "models") -> bool:
    global _active_ort_session, _active_version
    global _candidate_ort_session, _candidate_version
    global _tokenizer, _observer
    
    # Use fast tokenizer directly to drop PyTorch dependency
    from transformers import AutoTokenizer
    try:
        # Load from hub or local cache (fast Rust tokenizer)
        _tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased", use_fast=True)
    except Exception as e:
        logger.error(f"Failed to load tokenizer: {e}")
        return False
        
    _active_ort_session, _active_version = _load_prompt_model_version(models_dir, "prompt_active_version.txt")
    _candidate_ort_session, _candidate_version = _load_prompt_model_version(models_dir, "prompt_candidate_version.txt")
    
    loaded_any = False
    
    if _active_ort_session:
        logger.info(f"--- Prompt Injection Engine Ready ---")
        logger.info(f"Active Model: DistilBERT INT8 ONNX (Version: {_active_version})")
        loaded_any = True
        
    if _candidate_ort_session:
        logger.info(f"Candidate Model: DistilBERT INT8 ONNX (Version: {_candidate_version})")
        logger.info(f"Traffic Routing: {CANARY_TRAFFIC_PCT*100}%")
        loaded_any = True
            
    if loaded_any and _observer is None:
        event_handler = PromptModelReloadHandler()
        _observer = Observer()
        _observer.schedule(event_handler, path=os.path.abspath(models_dir), recursive=False)
        _observer.start()
        logger.info("Prompt Model watchdog observer started.")
        
    return loaded_any

from app.core.telemetry import track_latency, CANARY_LATENCY, CANARY_ERRORS
import time

def _sync_predict_prompt(prompt: str) -> dict:
    global _active_ort_session, _active_version
    global _candidate_ort_session, _candidate_version
    global _tokenizer
    
    use_canary = False
    if _candidate_ort_session is not None and random.random() < CANARY_TRAFFIC_PCT:
        use_canary = True
        
    target_session = _candidate_ort_session if use_canary else _active_ort_session
    target_version = _candidate_version if use_canary else _active_version
    
    if target_session is None or _tokenizer is None:
        return {"prediction": "unknown", "score": 0.0, "error": "Model not loaded"}
        
    start_t = time.perf_counter()
    try:
        # Tokenize (Max Length truncated during FastAPI validation, but bounded here as safety net)
        inputs = _tokenizer(prompt, return_tensors="np", truncation=True, max_length=128, padding="max_length")
        ort_inputs = {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        }
        
        # ONNX inference
        ort_outs = target_session.run(None, ort_inputs)
        logits = ort_outs[0]
        
        # Softmax
        exp_logits = np.exp(logits)
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
        score = float(probs[0][1])
        
        prediction = "injection" if score > 0.5 else "benign"
        
        if use_canary:
            CANARY_LATENCY.labels(version=target_version).observe(time.perf_counter() - start_t)
            
        return {
            "prediction": prediction,
            "score": score,
            "model_version": target_version,
            "is_canary": use_canary
        }
    except Exception as e:
        if use_canary:
            CANARY_ERRORS.labels(version=target_version).inc()
        logger.error(f"Prompt inference error: {e}")
        return {"prediction": "unknown", "score": 0.0, "error": str(e)}

@track_latency(module="prompt", stage="inference")
async def predict_prompt(prompt: str) -> dict:
    # Offload CPU-bound ONNX execution from the FastAPI Event Loop
    return await asyncio.to_thread(_sync_predict_prompt, prompt)
