import os
import sys
import csv
import numpy as np
import pandas as pd
import joblib
import shap
from sklearn.model_selection import GroupShuffleSplit

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

def main():
    filepath = "data/dataset.csv"
    X_list = []
    y_list = []
    groups_list = []
    urls_list = []
    feature_names = None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = row['url']
            label = int(row['label'])
            
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
            groups_list.append(normalized.get("domain", ""))
            urls_list.append(raw_url)

    X = np.array(X_list)
    y = np.array(y_list)
    groups = np.array(groups_list)
    urls = np.array(urls_list)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.10, random_state=42)
    train_val_idx, test_idx = next(gss.split(X, y, groups))
    
    X_test = X[test_idx]
    y_test = y[test_idx]
    urls_test = urls[test_idx]
    
    pipeline = joblib.load("models/lgbm_calibrated.joblib")
    clf = pipeline["model"]
    base_lgbm = clf.calibrated_classifiers_[0].estimator.estimator
    
    with open("models/optimal_threshold.txt", "r") as f:
        best_thresh = float(f.read().strip())
        
    y_test_proba = clf.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_proba >= best_thresh).astype(int)
    
    # 1. False Negatives
    fn_mask = (y_test == 1) & (y_test_pred == 0)
    fn_urls = urls_test[fn_mask]
    fn_probas = y_test_proba[fn_mask]
    
    print("--- 8 FALSE NEGATIVES (y=1, pred=0) ---")
    for u, p in zip(fn_urls, fn_probas):
        print(f"Prob: {p:.4f} | {u}")
        
    # 2. SHAP Feature Importances
    print("\n--- SHAP Feature Importances (Mean Absolute) ---")
    explainer = shap.TreeExplainer(base_lgbm)
    shap_values = explainer.shap_values(X_test)
    
    # For binary classification, shap_values might be a list of 2 arrays or a single array
    if isinstance(shap_values, list):
        shap_vals = shap_values[1] # positive class
    else:
        shap_vals = shap_values
        
    mean_abs_shap = np.abs(shap_vals).mean(axis=0)
    top_indices = np.argsort(mean_abs_shap)[::-1][:20]
    
    for idx in top_indices:
        print(f"{feature_names[idx]:<30}: {mean_abs_shap[idx]:.4f}")

if __name__ == "__main__":
    main()
