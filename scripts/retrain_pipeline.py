#!/usr/bin/env python3
"""
TrustGuard Monthly Retraining Pipeline
Run: python scripts/retrain_pipeline.py
Schedule: cron 0 2 1 * * (2am on 1st of each month)
"""

import os
import sys

# Ensure the app module can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import csv
import io
import joblib
import logging
import zipfile
from datetime import datetime
from unittest.mock import patch

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

logger = logging.getLogger(__name__)

MODEL_PATH = "models/phishing_rf.joblib"
PHISHING_FEEDS = [
    "http://data.phishtank.com/data/online-valid.csv",
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/csv_recent/",
]
LEGIT_FEED = "https://tranco-list.eu/top-1m.csv.zip"

def fetch_phishing_urls() -> list[str]:
    urls = []
    logger.info("Fetching phishing feeds...")
    try:
        # OpenPhish plain text
        r = httpx.get(PHISHING_FEEDS[1], timeout=30)
        urls += r.text.strip().splitlines()
        
        # URLHaus CSV (comments start with #)
        r2 = httpx.get(PHISHING_FEEDS[2], timeout=30)
        reader2 = csv.reader(io.StringIO(r2.text))
        for row in reader2:
            if not row or row[0].startswith('#'):
                continue
            if len(row) > 2:
                urls.append(row[2])
    except Exception as e:
        logger.error(f"Error fetching phishing feeds: {e}")
        
    logger.info(f"Fetched {len(urls)} phishing URLs")
    return urls[:1000]  # Cap for retraining speed and balance

def fetch_legit_urls() -> list[str]:
    urls = []
    logger.info("Fetching legit feeds...")
    try:
        r = httpx.get(LEGIT_FEED, timeout=60)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        with z.open("top-1m.csv") as f:
            reader = csv.reader(io.TextIOWrapper(f))
            urls = [f"https://{row[1]}" for row in reader if len(row) > 1]
    except Exception as e:
        logger.error(f"Error fetching legit feeds: {e}")
        
    logger.info(f"Fetched {len(urls)} legitimate URLs")
    return urls[:1000] # Cap for retraining speed and balance

def build_dataset(phishing: list, legit: list) -> pd.DataFrame:
    rows = []
    
    # Mock WHOIS to prevent timing out on thousands of requests during bulk training
    with patch('app.core.extractor.get_domain_age_days', return_value=None):
        logger.info("Extracting features for phishing URLs...")
        for url in phishing:
            try:
                norm = normalize_url(url)
                feats = extract_features(norm)
                # Ensure correct ordering and extraction for training
                row = {
                    "url_length": float(feats.get("url_length", 0)),
                    "domain_length": float(feats.get("domain_length", 0)),
                    "subdomain_count": float(feats.get("subdomain_count", 0)),
                    "has_special_chars": 1.0 if feats.get("has_special_chars") else 0.0,
                    "entropy": float(feats.get("entropy", 0.0)),
                    "suspicious_keywords": float(feats.get("suspicious_keywords", 0)),
                    "label": 1
                }
                rows.append(row)
            except Exception:
                pass
                
        logger.info("Extracting features for legit URLs...")
        for url in legit:
            try:
                norm = normalize_url(url)
                feats = extract_features(norm)
                row = {
                    "url_length": float(feats.get("url_length", 0)),
                    "domain_length": float(feats.get("domain_length", 0)),
                    "subdomain_count": float(feats.get("subdomain_count", 0)),
                    "has_special_chars": 1.0 if feats.get("has_special_chars") else 0.0,
                    "entropy": float(feats.get("entropy", 0.0)),
                    "suspicious_keywords": float(feats.get("suspicious_keywords", 0)),
                    "label": 0
                }
                rows.append(row)
            except Exception:
                pass
                
    return pd.DataFrame(rows)

def train_and_save(df: pd.DataFrame):
    if df.empty:
        logger.error("Dataset is empty. Cannot train.")
        return
        
    X = df.drop("label", axis=1)
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    report = classification_report(y_test, model.predict(X_test))
    logger.info(f"Model performance:\n{report}")
    
    # Save with timestamp backup
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    backup_path = f"models/phishing_rf_{ts}.joblib"
    joblib.dump(model, backup_path)
    
    # Overwrite active model to trigger Watchdog reload
    joblib.dump(model, MODEL_PATH)
    logger.info(f"Active model saved to {MODEL_PATH}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info("Starting retraining pipeline...")
    
    # Create models directory if it doesn't exist
    os.makedirs("models", exist_ok=True)
    
    phishing_urls = fetch_phishing_urls()
    legit_urls    = fetch_legit_urls()
    
    df = build_dataset(phishing_urls, legit_urls)
    logger.info(f"Dataset compiled: {len(df)} samples")
    
    train_and_save(df)
    logger.info("Retraining complete.")
