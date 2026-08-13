import os
import csv
import httpx
import zipfile
import io
import sys

# Ensure app imports work when run from root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.normalizer import normalize_url
from app.core.extractor import extract_features
import app.core.extractor
app.core.extractor.cached_whois = lambda domain: None

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"

SAFE_SAMPLES = 5000
PHISHING_SAMPLES = 5000

def fetch_tranco(client: httpx.Client, limit: int = SAFE_SAMPLES):
    print("Fetching Tranco list...")
    response = client.get(TRANCO_URL)
    response.raise_for_status()
    
    urls = []
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        filename = z.namelist()[0]
        with z.open(filename) as f:
            reader = csv.reader(io.TextIOWrapper(f, 'utf-8'))
            for row in reader:
                if len(urls) >= limit:
                    break
                # Tranco has (rank, domain)
                if len(row) >= 2:
                    urls.append(f"http://{row[1]}")
    return urls

def fetch_openphish(client: httpx.Client, limit: int = PHISHING_SAMPLES // 2):
    print("Fetching OpenPhish list...")
    response = client.get(OPENPHISH_URL)
    response.raise_for_status()
    
    urls = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and len(urls) < limit:
            urls.append(line)
    return urls

def fetch_urlhaus(client: httpx.Client, limit: int = PHISHING_SAMPLES // 2):
    print("Fetching URLHaus list...")
    response = client.get(URLHAUS_URL)
    response.raise_for_status()
    
    urls = []
    # URLHaus is a CSV, lines starting with # are comments
    reader = csv.reader(response.text.splitlines())
    for row in reader:
        if not row or row[0].startswith('#'):
            continue
        if len(urls) >= limit:
            break
        if len(row) >= 3:
            # urlhaus: id, dateadded, url, ...
            urls.append(row[2])
    return urls

def process_and_save(urls_with_labels, output_file):
    print(f"Processing and saving {len(urls_with_labels)} records to {output_file}...")
    
    fieldnames = [
        "url", "label", "url_length", "domain_length", 
        "subdomain_count", "has_special_chars", "entropy", "suspicious_keywords"
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for url, label in urls_with_labels:
            try:
                normalized = normalize_url(url)
                features = extract_features(normalized)
                
                row = {"url": url, "label": label}
                row.update(features)
                writer.writerow(row)
            except Exception as e:
                print(f"Failed to process {url}: {e}")

def main():
    os.makedirs("data", exist_ok=True)
    output_file = "data/dataset.csv"
    
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        safe_urls = fetch_tranco(client, SAFE_SAMPLES)
        openphish_urls = fetch_openphish(client, PHISHING_SAMPLES // 2)
        urlhaus_urls = fetch_urlhaus(client, PHISHING_SAMPLES - len(openphish_urls))
        
    dataset = [(url, 0) for url in safe_urls] + [(url, 1) for url in openphish_urls + urlhaus_urls]
    
    process_and_save(dataset, output_file)
    print("Dataset generation complete!")

if __name__ == "__main__":
    main()
