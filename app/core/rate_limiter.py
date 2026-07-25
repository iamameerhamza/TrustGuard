import time
from fastapi import Request, HTTPException

import os

# Simple in-memory sliding window rate limiter
_requests = {}
LIMIT = int(os.getenv("RATE_LIMIT", "60"))  # requests per minute
WINDOW = 60  # seconds

def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    current_time = time.time()
    
    if client_ip not in _requests:
        _requests[client_ip] = []
        
    # Remove old timestamps outside the window
    _requests[client_ip] = [ts for ts in _requests[client_ip] if current_time - ts < WINDOW]
    
    if len(_requests[client_ip]) >= LIMIT:
        raise HTTPException(status_code=429, detail="Too Many Requests")
        
    _requests[client_ip].append(current_time)
