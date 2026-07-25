import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("TRUSTGUARD_API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(api_key_header)):
    """Dependency that enforces a valid API key on protected routes.

    If TRUSTGUARD_API_KEY is unset, auth is disabled (dev mode) and a warning
    is printed at import time so it is not silently insecure.
    """
    if not API_KEY:
        # Auth disabled — allow through but this is flagged at startup.
        return
    if not key or key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


if not API_KEY:
    print(
        "WARNING: TRUSTGUARD_API_KEY is not set. The API is running WITHOUT "
        "authentication. Set it in your .env before deploying."
    )
