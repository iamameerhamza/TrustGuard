import requests
import threading
import time
import statistics

API_URL = "http://localhost:8000/scan"
NUM_REQUESTS = 100
CONCURRENT_THREADS = 10

latencies = []
errors = 0

def make_request():
    global errors
    payload = {"url": "http://example.com/test-load-1234"}
    try:
        start_time = time.time()
        response = requests.post(API_URL, json=payload, timeout=5)
        end_time = time.time()
        if response.status_code == 200:
            latencies.append(end_time - start_time)
        else:
            errors += 1
    except requests.exceptions.RequestException:
        errors += 1

def run_load_test():
    print(f"Starting load test with {NUM_REQUESTS} requests across {CONCURRENT_THREADS} threads...")
    threads = []
    
    start_total = time.time()
    for _ in range(NUM_REQUESTS):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()
        
        # Limit concurrency
        if len(threads) >= CONCURRENT_THREADS:
            for t in threads:
                t.join()
            threads = []
            
    # Join remaining
    for t in threads:
        t.join()
        
    end_total = time.time()
    
    print("\n--- Load Test Results ---")
    print(f"Total time elapsed: {end_total - start_total:.2f}s")
    print(f"Successful requests: {len(latencies)}")
    print(f"Errors: {errors}")
    if latencies:
        print(f"Average latency: {statistics.mean(latencies):.4f}s")
        print(f"Median latency: {statistics.median(latencies):.4f}s")
        print(f"Max latency: {max(latencies):.4f}s")
        print(f"Min latency: {min(latencies):.4f}s")

if __name__ == "__main__":
    run_load_test()
