import asyncio
import httpx
import time
import base64
import os

# Ensure the server is running on localhost:8000 before executing this script.

async def slow_request(client):
    # Create a dummy large PDF (just a bunch of bytes) to force PyPDF/pikepdf to chew on it
    # We'll simulate a 1MB payload
    dummy_pdf = b"%PDF-1.4\n" + (b"A" * 1024 * 1024) + b"\n%%EOF"
    b64_pdf = base64.b64encode(dummy_pdf).decode()
    payload = {
        "filename": "heavy.pdf",
        "content_base64": b64_pdf,
        "mime_type": "application/pdf"
    }
    
    start = time.perf_counter()
    resp = await client.post("http://localhost:8000/v1/scan/document/", json=payload, timeout=20.0)
    end = time.perf_counter()
    
    # We expect a 200 or 500/504 depending on parsing limits, the point is it blocks CPU
    return {"type": "heavy_doc", "time": end - start, "status": resp.status_code}

async def fast_request(client):
    payload = {"url": "https://example.com"}
    start = time.perf_counter()
    resp = await client.post("http://localhost:8000/v1/scan/url/", json=payload, timeout=5.0)
    end = time.perf_counter()
    
    return {"type": "light_url", "time": end - start, "status": resp.status_code}

async def main():
    async with httpx.AsyncClient() as client:
        print("Warming up URL scan endpoint...")
        await fast_request(client)
        
        print("Firing 5 heavy document scans concurrently...")
        heavy_tasks = [asyncio.create_task(slow_request(client)) for _ in range(5)]
        
        # Wait a tiny bit so the heavy tasks hit the event loop and start churning CPU
        await asyncio.sleep(0.1)
        
        print("Firing 5 lightweight URL scans while the server is under heavy load...")
        light_tasks = [asyncio.create_task(fast_request(client)) for _ in range(5)]
        
        results = await asyncio.gather(*(light_tasks + heavy_tasks))
        
        light_times = [r["time"] for r in results if r["type"] == "light_url"]
        heavy_times = [r["time"] for r in results if r["type"] == "heavy_doc"]
        
        print("\n--- Concurrency Test Results ---")
        print(f"Avg Lightweight URL Scan Time: {sum(light_times)/len(light_times)*1000:.2f} ms")
        print(f"Max Lightweight URL Scan Time: {max(light_times)*1000:.2f} ms")
        print(f"Avg Heavy Document Scan Time: {sum(heavy_times)/len(heavy_times):.2f} seconds")
        
        # If the event loop was blocked, the URL scans would take seconds (waiting for the heavy scans).
        # Since we used asyncio.to_thread, URL scans should still take milliseconds.
        if max(light_times) < 0.5:
            print("SUCCESS: Event loop is shielded. Async offloading is working perfectly.")
        else:
            print("WARNING: Event loop might be blocked. URL scans took suspiciously long.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Test failed: {e}")
