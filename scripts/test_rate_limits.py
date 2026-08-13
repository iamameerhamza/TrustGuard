import asyncio
import httpx
import time
import base64

async def scan_doc(client):
    dummy_pdf = b"%PDF-1.4\n" + b"dummy\n%%EOF"
    payload = {
        "filename": "heavy.pdf",
        "content_base64": base64.b64encode(dummy_pdf).decode(),
        "mime_type": "application/pdf"
    }
    resp = await client.post("http://localhost:8000/scan/document/", json=payload, headers={"X-API-Key": "change_me_to_a_strong_random_secret"})
    return {"type": "doc", "status": resp.status_code}

async def scan_url(client):
    payload = {"url": "https://example.com"}
    resp = await client.post("http://localhost:8000/scan", json=payload, headers={"X-API-Key": "change_me_to_a_strong_random_secret"})
    return {"type": "url", "status": resp.status_code}

async def main():
    # Note: ensure server is running
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Fire 20 document scans (limit is 10/minute, so at least 10 should 429)
        doc_tasks = [asyncio.create_task(scan_doc(client)) for _ in range(20)]
        # Fire 20 URL scans (limit is 100/minute, so all should be 200)
        url_tasks = [asyncio.create_task(scan_url(client)) for _ in range(20)]
        
        results = await asyncio.gather(*(doc_tasks + url_tasks))
        
        doc_statuses = [r["status"] for r in results if r["type"] == "doc"]
        url_statuses = [r["status"] for r in results if r["type"] == "url"]
        
        print("Document Scan Statuses:", {s: doc_statuses.count(s) for s in set(doc_statuses)})
        print("URL Scan Statuses:", {s: url_statuses.count(s) for s in set(url_statuses)})
        
        if 429 in doc_statuses and 429 not in url_statuses:
            print("SUCCESS: Rate Limit Isolation verified. Document scans were throttled, but URL scans passed.")
        else:
            print("WARNING: Rate limit isolation failed or was not triggered as expected.")

if __name__ == "__main__":
    asyncio.run(main())
