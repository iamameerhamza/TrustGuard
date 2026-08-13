import os
import httpx
import random
import pandas as pd
import zipfile
import io

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

def fetch_tranco_long_tail(count: int = 2000):
    print("Downloading Tranco top 1M list...")
    resp = httpx.get(TRANCO_URL, follow_redirects=True, timeout=30.0)
    resp.raise_for_status()
    print("Extracting...")
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        filename = z.namelist()[0]
        with z.open(filename) as f:
            df = pd.read_csv(f, names=['rank', 'domain'])
            
    # Filter for long-tail domains (rank 100,000 to 1,000,000)
    long_tail = df[(df['rank'] >= 100000) & (df['rank'] <= 1000000)]
    return long_tail['domain'].sample(count).tolist()

def generate_hard_negatives(domains):
    urls = []
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
    
    for domain in domains:
        choice = random.random()
        if choice < 0.2:
            # 20%: Just the obscure domain
            urls.append(f"https://{domain}/")
        elif choice < 0.4:
            # 20%: Deep path on obscure domain
            urls.append(f"https://{domain}/wp-content/uploads/2026/07/doc.pdf")
        elif choice < 0.6:
            # 20%: Obscure domain with query params that look suspicious
            urls.append(f"https://{domain}/login.php?redirect=secure&id={random.randint(100, 999)}")
        elif choice < 0.8:
            # 20%: URL Shortener (synthetic generation)
            short = random.choice(shorteners)
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=random.randint(5, 8)))
            urls.append(f"https://{short}/{token}")
        else:
            # 20%: IP Address (legit routing, e.g. local routers, non-malicious servers)
            ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            urls.append(f"http://{ip}/admin")
            
    return urls

def main():
    domains = fetch_tranco_long_tail(count=2000)
    hard_urls = generate_hard_negatives(domains)
    
    # Save to dataset
    dataset_path = "data/dataset.csv"
    if os.path.exists(dataset_path):
        df_existing = pd.read_csv(dataset_path)
    else:
        df_existing = pd.DataFrame(columns=["url", "label"])
        
    df_new = pd.DataFrame({"url": hard_urls, "label": [0] * len(hard_urls)})
    df_combined = pd.concat([df_existing, df_new], ignore_index=True)
    
    # Remove exact duplicates
    df_combined = df_combined.drop_duplicates(subset=['url'])
    
    df_combined.to_csv(dataset_path, index=False)
    print(f"Added {len(hard_urls)} hard negatives. New dataset size: {len(df_combined)}")

if __name__ == "__main__":
    main()
