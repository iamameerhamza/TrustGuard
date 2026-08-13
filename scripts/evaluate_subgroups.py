import os
import sys
import csv
import numpy as np
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

def main():
    filepath = "data/dataset.csv"
    X_list = []
    y_list = []
    groups_list = []
    is_hard_negative_list = []
    feature_names = None
    
    print("Loading dataset and extracting features...")
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            raw_url = row['url']
            label = int(row['label'])
            
            # The original dataset was exactly 10,000 rows.
            # The newly appended 2,000 hard negatives start at index 10000.
            is_hard = (i >= 10000)
            
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
            is_hard_negative_list.append(is_hard)

    X = np.array(X_list)
    y = np.array(y_list)
    groups = np.array(groups_list)
    is_hard_negative = np.array(is_hard_negative_list)
    
    print(f"Total dataset shape: {X.shape}, Hard Negatives: {np.sum(is_hard_negative)}")

    # 1. Split out Test set exactly as train_model.py did
    gss = GroupShuffleSplit(n_splits=1, test_size=0.10, random_state=42)
    train_val_idx, test_idx = next(gss.split(X, y, groups))
    
    X_test = X[test_idx]
    y_test = y[test_idx]
    is_hard_test = is_hard_negative[test_idx]
    
    print(f"Test set size: {X_test.shape[0]}, containing {np.sum(is_hard_test)} hard negatives.")
    
    # 2. Load Model and Threshold
    pipeline = joblib.load("models/lgbm_calibrated.joblib")
    clf = pipeline["model"]
    
    with open("models/optimal_threshold.txt", "r") as f:
        best_thresh = float(f.read().strip())
        
    y_test_proba = clf.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_proba >= best_thresh).astype(int)
    
    # 3. Analyze Subgroups
    # Easy Negatives: y == 0 AND NOT is_hard
    # Hard Negatives: y == 0 AND is_hard
    # Positives (Phishing): y == 1
    
    easy_neg_mask = (y_test == 0) & (~is_hard_test)
    hard_neg_mask = (y_test == 0) & is_hard_test
    pos_mask = (y_test == 1)
    
    # Overall metrics
    print("\n--- OVERALL TEST METRICS ---")
    print(f"Total F1: {f1_score(y_test, y_test_pred):.4f}")
    
    fp_total = np.sum((y_test_pred == 1) & (y_test == 0))
    tn_total = np.sum((y_test_pred == 0) & (y_test == 0))
    print(f"Total FPR: {fp_total / (fp_total + tn_total):.4f} ({fp_total} FPs out of {fp_total + tn_total} negatives)")
    
    # Subgroup: Easy Negatives (Top 500)
    print("\n--- SUBGROUP: Easy Negatives (Tranco Top 500) ---")
    fp_easy = np.sum((y_test_pred == 1) & easy_neg_mask)
    tn_easy = np.sum((y_test_pred == 0) & easy_neg_mask)
    fpr_easy = fp_easy / (fp_easy + tn_easy) if (fp_easy + tn_easy) > 0 else 0
    print(f"Size: {np.sum(easy_neg_mask)}")
    print(f"FPR: {fpr_easy:.4f} ({fp_easy} FPs)")
    
    # Subgroup: Hard Negatives (Tranco 100k-1M + Synthetic Shorteners)
    print("\n--- SUBGROUP: Hard Negatives ---")
    fp_hard = np.sum((y_test_pred == 1) & hard_neg_mask)
    tn_hard = np.sum((y_test_pred == 0) & hard_neg_mask)
    fpr_hard = fp_hard / (fp_hard + tn_hard) if (fp_hard + tn_hard) > 0 else 0
    print(f"Size: {np.sum(hard_neg_mask)}")
    print(f"FPR: {fpr_hard:.4f} ({fp_hard} FPs)")
    
    # Subgroup: Phishing (True Positives)
    print("\n--- SUBGROUP: Phishing (Positives) ---")
    tp = np.sum((y_test_pred == 1) & pos_mask)
    fn = np.sum((y_test_pred == 0) & pos_mask)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    print(f"Size: {np.sum(pos_mask)}")
    print(f"Recall: {recall:.4f} ({tp} TPs, {fn} FNs)")

if __name__ == "__main__":
    main()
