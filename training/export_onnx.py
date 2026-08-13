"""
Export scikit-learn Random Forest to ONNX format.
Run this after training to generate the ONNX model for edge deployment.
"""
from __future__ import annotations
import json
import logging
import joblib
import numpy as np
from pathlib import Path
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def export_rf_to_onnx(
    model_path: str = "models/phishing_rf.joblib",
    output_path: str = "models/phishing_rf.onnx",
    feature_names: Optional[list[str]] = None,
    target_opset: int = 15,
) -> bool:
    """
    Export trained Random Forest model to ONNX format.
    
    Args:
        model_path: Path to trained joblib model
        output_path: Path to save ONNX model
        feature_names: Ordered list of feature names (must match training)
        target_opset: ONNX opset version (15 works well for sklearn-onnx)
        
    Returns:
        True if export successful
    """
    try:
        import skl2onnx
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        logger.error("skl2onnx not installed. Run: pip install skl2onnx onnxruntime")
        return False
    
    # Load model
    model_file = Path(model_path)
    if not model_file.exists():
        logger.error(f"Model not found: {model_path}")
        return False
    
    logger.info(f"Loading model from {model_path}")
    model = joblib.load(model_path)
    
    # Default feature names (must match extractor)
    if feature_names is None:
        feature_names = [
            "url_length",
            "domain_length", 
            "subdomain_count",
            "path_length",
            "query_length",
            "has_special_chars",
            "has_at_symbol",
            "has_dash_in_domain",
            "entropy",
            "suspicious_keyword_count",
            "is_ip_address",
            "has_port",
            "tld_risk_score",
            "brand_impersonation_score",
            "punycode_detected",
            "subdomain_entropy",
            "path_entropy",
            "query_param_count",
            "has_suspicious_tld",
            "url_hash_prefix",
        ]
    
    # Define input type: [batch_size, n_features]
    initial_type = [('float_input', FloatTensorType([None, len(feature_names)]))]
    
    # Convert to ONNX
    logger.info("Converting to ONNX...")
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=target_opset,
        options={'zipmap': False},  # Output raw probabilities
    )
    
    # Save ONNX model
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    logger.info(f"ONNX model saved to {output_path}")
    
    # Save metadata
    meta_path = output_file.with_suffix('.json')
    metadata = {
        "model_type": "RandomForestClassifier",
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "n_estimators": getattr(model, 'n_estimators', 'unknown'),
        "version": "1.0.0",
        "exported_with": "skl2onnx",
        "target_opset": target_opset,
    }
    
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"Metadata saved to {meta_path}")
    return True


def quantize_onnx_model(
    input_path: str = "models/phishing_rf.onnx",
    output_path: str = "models/phishing_rf_int8.onnx",
    quantization_mode: str = "dynamic",
) -> bool:
    """
    Quantize ONNX model to INT8 for smaller size and faster inference.
    
    Args:
        input_path: Path to FP32 ONNX model
        output_path: Path to save quantized model
        quantization_mode: 'dynamic' or 'static'
        
    Returns:
        True if quantization successful
    """
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
    except ImportError:
        logger.error("onnxruntime quantization tools not available")
        return False
    
    input_file = Path(input_path)
    if not input_file.exists():
        logger.error(f"Input model not found: {input_path}")
        return False
    
    logger.info(f"Quantizing {input_path} to INT8...")
    
    try:
        quantize_dynamic(
            model_input=str(input_file),
            model_output=str(output_path),
            weight_type=QuantType.QInt8,
        )
        
        # Verify quantized model
        import onnxruntime as ort
        session = ort.InferenceSession(str(output_path), providers=['CPUExecutionProvider'])
        logger.info(f"Quantized model saved to {output_path}")
        logger.info(f"Model size reduction: {input_file.stat().st_size / 1024:.1f} KB -> {Path(output_path).stat().st_size / 1024:.1f} KB")
        
        return True
        
    except Exception as e:
        logger.error(f"Quantization failed: {e}")
        return False


def verify_onnx_model(
    onnx_path: str = "models/phishing_rf.onnx",
    test_input: Optional[np.ndarray] = None,
) -> bool:
    """
    Verify ONNX model loads and runs correctly.
    
    Args:
        onnx_path: Path to ONNX model
        test_input: Optional test input array
        
    Returns:
        True if verification passes
    """
    try:
        import onnxruntime as ort
    except ImportError:
        logger.error("onnxruntime not installed")
        return False
    
    onnx_file = Path(onnx_path)
    if not onnx_file.exists():
        logger.error(f"Model not found: {onnx_path}")
        return False
    
    try:
        # Load session
        session = ort.InferenceSession(str(onnx_file), providers=['CPUExecutionProvider'])
        
        # Get input info
        input_name = session.get_inputs()[0].name
        input_shape = session.get_inputs()[0].shape
        logger.info(f"Model input: {input_name} {input_shape}")
        
        # Run test inference
        if test_input is None:
            # Random test input
            test_input = np.random.rand(1, input_shape[1]).astype(np.float32)
        
        outputs = session.run(None, {input_name: test_input})
        logger.info(f"Test inference successful. Output shape: {outputs[0].shape}")
        logger.info(f"Output values: {outputs[0]}")
        
        return True
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    # Default paths
    model_path = sys.argv[1] if len(sys.argv) > 1 else "models/phishing_rf.joblib"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "models/phishing_rf.onnx"
    
    # Export
    success = export_rf_to_onnx(model_path, output_path)
    
    if success:
        # Verify
        verify_onnx_model(output_path)
        
        # Optional: quantize
        quantize_path = output_path.replace('.onnx', '_int8.onnx')
        quantize_onnx_model(output_path, quantize_path)
        
        print("\n✅ Export complete!")
        print(f"   FP32 model: {output_path}")
        print(f"   INT8 model: {quantize_path}")
        print(f"   Metadata: {output_path.replace('.onnx', '.json')}")
    else:
        print("\n❌ Export failed!")
        sys.exit(1)