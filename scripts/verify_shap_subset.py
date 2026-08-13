import os
import sys
import csv
import numpy as np
import joblib
import shap

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

def main():
    filepath = "data/dataset.csv"
    X_list = []
    feature_names = None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = row['url']
            try:
                normalized = normalize_url(raw_url)
            except Exception:
                normalized = {"url": raw_url, "domain": raw_url.split('/')[2] if '//' in raw_url else raw_url.split('/')[0]}
            
            feats_dict = extract_features(normalized)
            if feature_names is None:
                feature_names = sorted(list(feats_dict.keys()))
                
            X_list.append([feats_dict[k] for k in feature_names])

    X = np.array(X_list)
    
    pipeline = joblib.load("models/lgbm_calibrated.joblib")
    clf = pipeline["model"]
    base_lgbm = clf.calibrated_classifiers_[0].estimator.estimator
    
    non_ascii_idx = feature_names.index("non_ascii_ratio")
    brand_lev_idx = feature_names.index("brand_spoof_risk")
    
    # Identify subsets
    # Homoglyphs (non_ascii_ratio > 0)
    homoglyph_mask = X[:, non_ascii_idx] > 0
    X_homoglyph = X[homoglyph_mask]
    
    # Brand Spoofs (brand_spoof_risk > 0)
    brand_mask = X[:, brand_lev_idx] > 0
    X_brand = X[brand_mask]
    
    print(f"Total Dataset Size: {X.shape[0]}")
    print(f"Rows with Homoglyph (non_ascii_ratio > 0): {np.sum(homoglyph_mask)}")
    print(f"Rows with Brand Match (brand_spoof_risk > 0): {np.sum(brand_mask)}")
    
    explainer = shap.TreeExplainer(base_lgbm)
    
    if np.sum(homoglyph_mask) > 0:
        print("\n--- SHAP Feature Importances for HOMOGLYPH Subset ---")
        shap_values_homo = explainer.shap_values(X_homoglyph)
        if isinstance(shap_values_homo, list):
            shap_vals_h = shap_values_homo[1]
        else:
            shap_vals_h = shap_values_homo
            
        mean_abs_shap_h = np.abs(shap_vals_h).mean(axis=0)
        top_h = np.argsort(mean_abs_shap_h)[::-1][:10]
        for idx in top_h:
            print(f"{feature_names[idx]:<30}: {mean_abs_shap_h[idx]:.4f}")
            
    if np.sum(brand_mask) > 0:
        print("\n--- SHAP Feature Importances for BRAND MATCH Subset ---")
        shap_values_brand = explainer.shap_values(X_brand)
        if isinstance(shap_values_brand, list):
            shap_vals_b = shap_values_brand[1]
        else:
            shap_vals_b = shap_values_brand
            
        mean_abs_shap_b = np.abs(shap_vals_b).mean(axis=0)
        top_b = np.argsort(mean_abs_shap_b)[::-1][:10]
        for idx in top_b:
            print(f"{feature_names[idx]:<30}: {mean_abs_shap_b[idx]:.4f}")

if __name__ == "__main__":
    main()
