import os
import httpx
import csv

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"

def main():
    os.makedirs("data", exist_ok=True)
    output_file = "data/blacklist.txt"
    
    urls = set()
    
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        print("Fetching OpenPhish feed...")
        try:
            resp = client.get(OPENPHISH_URL)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if line:
                    urls.add(line)
        except Exception as e:
            print(f"Error fetching OpenPhish: {e}")

        print("Fetching URLHaus feed...")
        try:
            resp = client.get(URLHAUS_URL)
            resp.raise_for_status()
            reader = csv.reader(resp.text.splitlines())
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                if len(row) >= 3:
                    urls.add(row[2].strip())
        except Exception as e:
            print(f"Error fetching URLHaus: {e}")

    print(f"Writing {len(urls)} URLs to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(f"{url}\n")
            
    print("Blacklist updated successfully!")

if __name__ == "__main__":
    main()
