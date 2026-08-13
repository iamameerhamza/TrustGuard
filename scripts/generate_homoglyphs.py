import json
import csv
import random
import os

def generate_homoglyphs():
    # Load top brands
    brands_path = os.path.join("data", "top_brands.json")
    with open(brands_path, "r", encoding="utf-8") as f:
        brands = json.load(f)
        
    homoglyph_map = {
        'a': ['ą', 'ä', 'á', 'à', 'â'],
        'e': ['ẹ', 'é', 'è', 'ê', 'ë'],
        'i': ['ı', 'í', 'ì', 'î', 'ï', 'l', '1'],
        'o': ['ọ', 'ó', 'ò', 'ô', 'ö', '0'],
        'l': ['I', '1'],
        'u': ['ụ', 'ú', 'ù', 'û', 'ü'],
        'c': ['ç', 'ć'],
        'n': ['ñ', 'ń'],
        'y': ['ý', 'ÿ']
    }
    
    out_path = os.path.join("data", "homoglyphs.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "base_brand"])
        
        for brand in brands:
            # Generate True Negatives (legitimate brand instances)
            writer.writerow([f"https://www.{brand}.com/", 0, brand])
            writer.writerow([f"https://{brand}.com/login", 0, brand])
            writer.writerow([f"https://support.{brand}.com/", 0, brand])
            
            # Generate True Positives (Homoglyphs)
            for _ in range(5):
                # Pick a random character to replace
                chars = list(brand)
                replaceable_indices = [i for i, c in enumerate(chars) if c in homoglyph_map]
                if replaceable_indices:
                    idx = random.choice(replaceable_indices)
                    chars[idx] = random.choice(homoglyph_map[chars[idx]])
                    fake_brand = "".join(chars)
                    writer.writerow([f"https://www.{fake_brand}.com/login", 1, brand])
                    
            # Generate True Positives (Levenshtein typosquats)
            for _ in range(5):
                chars = list(brand)
                mutation = random.choice(["insert", "delete", "duplicate"])
                if mutation == "insert" and len(chars) > 2:
                    idx = random.randint(1, len(chars)-1)
                    chars.insert(idx, "-")
                elif mutation == "delete" and len(chars) > 4:
                    idx = random.randint(1, len(chars)-2)
                    chars.pop(idx)
                elif mutation == "duplicate" and len(chars) > 2:
                    idx = random.randint(1, len(chars)-1)
                    chars.insert(idx, chars[idx])
                
                fake_brand = "".join(chars)
                if fake_brand != brand:
                    writer.writerow([f"https://{fake_brand}.net/secure", 1, brand])

if __name__ == "__main__":
    generate_homoglyphs()
    print("Generated data/homoglyphs.csv")
