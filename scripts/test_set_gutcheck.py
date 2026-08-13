import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
import joblib
import urllib.parse
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.core.extractor import extract_features
from app.core.normalizer import normalize_url
import numpy as np

# Load Data
df = pd.read_csv("data/dataset.csv")

def get_domain(url):
    try:
        netloc = urllib.parse.urlparse(url).netloc
        if not netloc:
            netloc = url.split("/")[0]
        return netloc.lower()
    except:
        return str(url).lower()

df['domain'] = df['url'].apply(get_domain)

X = df['url']
y = df['label']
groups = df['domain']

gss = GroupShuffleSplit(n_splits=1, test_size=0.10, random_state=42)
for train_idx, test_idx in gss.split(X, y, groups):
    df_test = df.iloc[test_idx]
    break

# 1. Class Balance
print(f"Test Set Size: {len(df_test)}")
print("Class Balance:")
print(df_test['label'].value_counts())

# 2. Spot Check Borderline Cases
print("\nSpot Checking a few cases...")
model_pipeline = joblib.load("models/lgbm_calibrated.joblib")
model = model_pipeline['model']
feature_names = model_pipeline['feature_names']

probas = []
for url in df_test['url']:
    try:
        norm = normalize_url(url)
        feats = extract_features(norm)
        X_vec = np.array([[float(feats.get(k, 0.0)) for k in feature_names]])
        proba = model.predict_proba(X_vec)[0, 1]
    except Exception as e:
        proba = -1.0
    probas.append(proba)

df_test = df_test.copy()
df_test['ml_score'] = probas

print("\n--- Top 5 Most 'Suspicious' Legitimate Domains ---")
print(df_test[df_test['label'] == 0].sort_values('ml_score', ascending=False)[['url', 'ml_score']].head(5).to_string(index=False))

print("\n--- Top 5 Most 'Benign-Looking' Phishing Domains ---")
print(df_test[df_test['label'] == 1].sort_values('ml_score', ascending=True)[['url', 'ml_score']].head(5).to_string(index=False))
