import os
import sys
import csv
import logging
import joblib
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import GroupShuffleSplit
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, f1_score, confusion_matrix, roc_curve

# Add project root to sys.path so we can import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_and_extract_features(filepaths):
    X_list = []
    y_list = []
    groups_list = []
    feature_names = None
    
    for filepath in filepaths:
        logger.info(f"Loading {filepath}...")
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_url = row['url']
                label = int(row['label'])
                base_brand = row.get('base_brand', '').strip()
                
                try:
                    normalized = normalize_url(raw_url)
                except Exception:
                    normalized = {"url": raw_url, "domain": raw_url.split('/')[2] if '//' in raw_url else raw_url.split('/')[0]}
                
                feats_dict = extract_features(normalized)
                
                if feature_names is None:
                    feature_names = sorted(list(feats_dict.keys()))
                
                X_row = [feats_dict[k] for k in feature_names]
                X_list.append(X_row)
                y_list.append(label)
                
                # Use base_brand if available, else fallback to domain
                groups_list.append(base_brand if base_brand else normalized.get("domain", ""))
                
    return np.array(X_list), np.array(y_list), np.array(groups_list), feature_names

def main():
    import datetime
    import shutil
    import json
    
    version = f"v_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    data_paths = ["data/dataset.csv", "data/homoglyphs.csv"]
    model_dir = os.path.join("models", version)
    os.makedirs(model_dir, exist_ok=True)
    
    model_path = os.path.join(model_dir, "lgbm_calibrated.joblib")
    thresh_path = os.path.join(model_dir, "optimal_threshold.txt")
    dist_path = os.path.join(model_dir, "val_distribution.json")
    
    # Snapshot data
    for path in data_paths:
        if os.path.exists(path):
            shutil.copy2(path, os.path.join(model_dir, os.path.basename(path)))
            
    logger.info(f"--- Training Version {version} ---")
    logger.info(f"Loading data and dynamically extracting features from {data_paths}...")
    X, y, groups, feature_names = load_and_extract_features(data_paths)
    
    logger.info(f"Dataset shape: {X.shape}. Feature count: {len(feature_names)}")
    
    # 1. Split out Test set (10%) to prevent any leakage in final metrics
    gss = GroupShuffleSplit(n_splits=1, test_size=0.10, random_state=42)
    train_val_idx, test_idx = next(gss.split(X, y, groups))
    
    X_main, y_main, groups_main = X[train_val_idx], y[train_val_idx], groups[train_val_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    
    # 2. Split main into Train (approx 60%), Tune (15%), Calibrate (15%)
    gss_main = GroupShuffleSplit(n_splits=1, test_size=0.333, random_state=42)
    train_idx, val_calib_idx = next(gss_main.split(X_main, y_main, groups_main))
    
    X_train, y_train = X_main[train_idx], y_main[train_idx]
    X_val_calib, y_val_calib, groups_val_calib = X_main[val_calib_idx], y_main[val_calib_idx], groups_main[val_calib_idx]
    
    # 3. Split val_calib into Tune (50%) and Calibrate (50%)
    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    tune_idx, calib_idx = next(gss_val.split(X_val_calib, y_val_calib, groups_val_calib))
    
    X_tune, y_tune = X_val_calib[tune_idx], y_val_calib[tune_idx]
    X_calib, y_calib = X_val_calib[calib_idx], y_val_calib[calib_idx]
    
    logger.info(f"Split sizes: Train={X_train.shape[0]}, Tune={X_tune.shape[0]}, Calibrate={X_calib.shape[0]}, Test={X_test.shape[0]}")
    
    logger.info("Training base LightGBM Classifier...")
    base_lgbm = lgb.LGBMClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=7,
        num_leaves=31,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    # Fit base model only on Train, evaluate on Tune for early stopping
    base_lgbm.fit(
        X_train, y_train,
        eval_set=[(X_tune, y_tune)],
        callbacks=[lgb.early_stopping(stopping_rounds=20)]
    )
    
    from sklearn.frozen import FrozenEstimator
    logger.info("Calibrating model via Isotonic Scaling on the Calibrate holdout set...")
    calibrated_clf = CalibratedClassifierCV(FrozenEstimator(base_lgbm), method='isotonic')
    calibrated_clf.fit(X_calib, y_calib)
    
    # --- FIND OPTIMAL THRESHOLD ON TUNE SET (NO LEAKAGE INTO TEST) ---
    logger.info("Finding Optimal Operating Threshold on the Tune set...")
    y_tune_proba = calibrated_clf.predict_proba(X_tune)[:, 1]
    fpr, tpr, thresholds = roc_curve(y_tune, y_tune_proba)
    best_f1 = 0
    best_thresh = 0.5
    for thresh in thresholds:
        preds = (y_tune_proba >= thresh).astype(int)
        f1 = f1_score(y_tune, preds)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh
            
    logger.info(f"Selected Threshold from Tune set: {best_thresh:.4f}")
    
    # --- DRIFT BASELINE GENERATION ---
    logger.info("Generating val_distribution.json (Drift Baseline)...")
    hist, bin_edges = np.histogram(y_tune_proba, bins=20, range=(0.0, 1.0))
    hist_norm = hist / hist.sum()
    dist_data = {
        "version": version,
        "bins": bin_edges.tolist(),
        "probabilities": hist_norm.tolist()
    }
    with open(dist_path, "w") as f:
        json.dump(dist_data, f, indent=4)
    
    # --- REPORT TRUE PERFORMANCE ON UNTOUCHED TEST SET ---
    logger.info("Evaluating True Performance on untouched Test set...")
    y_test_proba = calibrated_clf.predict_proba(X_test)[:, 1]
    auc_score = roc_auc_score(y_test, y_test_proba)
    
    y_test_pred = (y_test_proba >= best_thresh).astype(int)
    final_f1 = f1_score(y_test, y_test_pred)
    
    # Calculate True FPR on test set
    fp = np.sum((y_test_pred == 1) & (y_test == 0))
    tn = np.sum((y_test_pred == 0) & (y_test == 0))
    final_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    cm_optimal = confusion_matrix(y_test, y_test_pred)
    
    logger.info(f"--- FINAL TEST METRICS ---")
    logger.info(f"ROC-AUC: {auc_score:.4f}")
    logger.info(f"F1-Score: {final_f1:.4f}")
    logger.info(f"True FPR: {final_fpr*100:.2f}%")
    logger.info(f"Confusion Matrix:\n{cm_optimal}")
    
    with open(thresh_path, "w") as f:
        f.write(str(best_thresh))
    
    calibrated_clf.calibrated_classifiers_[0].estimator.estimator.n_jobs = 1
    
    logger.info(f"Saving calibrated model and feature names to {model_path}...")
    pipeline = {
        "model": calibrated_clf,
        "feature_names": feature_names
    }
    joblib.dump(pipeline, model_path)
    
    # Write to candidate pointer atomically
    candidate_pointer = "models/candidate_version.txt"
    candidate_tmp = "models/candidate_version.tmp"
    with open(candidate_tmp, "w") as f:
        f.write(version)
    os.replace(candidate_tmp, candidate_pointer)
    
    # Write to active pointer ONLY if it doesn't exist
    active_pointer = "models/active_version.txt"
    if not os.path.exists(active_pointer):
        active_tmp = "models/active_version.tmp"
        with open(active_tmp, "w") as f:
            f.write(version)
        os.replace(active_tmp, active_pointer)
        logger.info(f"No active_version.txt found. Model automatically promoted to active: {version}")
    else:
        logger.info(f"Model saved as CANARY. Pointer updated at {candidate_pointer}")

if __name__ == "__main__":
    main()
