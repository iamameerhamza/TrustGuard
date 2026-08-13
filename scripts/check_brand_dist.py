import os
import sys
import csv
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.normalizer import normalize_url
from app.core.extractor import extract_features

def main():
    filepath = "data/dataset.csv"
    vals = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = row['url']
            try:
                normalized = normalize_url(raw_url)
            except Exception:
                normalized = {"url": raw_url, "domain": raw_url.split('/')[2] if '//' in raw_url else raw_url.split('/')[0]}
            
            feats = extract_features(normalized)
            vals.append(feats['brand_spoof_risk'])
            
    s = pd.Series(vals)
    print(s[s > 0].describe())

if __name__ == "__main__":
    main()
