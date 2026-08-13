import asyncio
import os
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging
logging.basicConfig(level=logging.DEBUG)
from app.main import app

def test_fn_urls():
    fn_urls = [
        "http://wundz.netlify.app/",
        "http://www.morcosit.com/",
        "https://www.lcdxw.cn/",
        "http://18438.xyz/",
        "https://lapidorseposoalovbs2.com/cleen_trs1.exe",
        "https://allendaltonproduction.com/quas/Client-built.exe",
        "https://grantexx.com/Pred.inf",
        "https://grantexx.com/Tilsee.cur"
    ]
    
    with TestClient(app) as client:
        print("Testing Full Fusion Pipeline on 8 FN URLs...\n")
        for url in fn_urls:
            print(f"--- Scanning: {url} ---")
            try:
                api_key = os.getenv("TRUSTGUARD_API_KEY", "change_me_to_a_strong_random_secret")
                response = client.post("/scan", json={"url": url}, headers={"X-API-Key": api_key})
                
                if response.status_code == 200:
                    data = response.json()
                    risk = data.get("risk_score")
                    prediction = data.get("prediction")
                    ml = data.get("ml_score")
                    vt = data.get("vt_score")
                    whois = data.get("whois", {}).get("score")
                    
                    print(f"Prediction: {prediction} | Risk Score: {risk}")
                    print(f"Breakdown -> ML: {ml}, VT: {vt}, WHOIS: {whois}")
                elif response.status_code == 429:
                    print("Rate limit exceeded.")
                else:
                    print(f"Failed: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"Error during scan: {e}")
            print()

if __name__ == "__main__":
    test_fn_urls()
