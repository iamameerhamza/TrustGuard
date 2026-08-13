import os
import asyncio
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.lifespan import lifespan
from app.core.auth import require_api_key
from app.core.rate_limit import limiter

from app.api.routes import history, report, scan
# from app.api.v1.anonymized_scan import router as anonymized_scan_router
from app.api.v1.qr_scan import router as qr_scan_router
from app.api.v1.platform_routes import router as platform_router
from app.api.v1.document_scan import router as document_scan_router
from app.api.v1.visual_scan import router as visual_scan_router
from app.api.v1.agentic_scan import router as agentic_scan_router
from app.api.v1.trust_seals import router as trust_seals_router

_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

app = FastAPI(
    title="TrustGuard API",
    description="Multi-modal threat intelligence API",
    version="2.1.0",
    lifespan=lifespan,
)

# 1. Prometheus Metrics Endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# 2. Rate Limiting Setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 3. Global Timeout Middleware (15s ceiling)
@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    # Do not timeout the metrics endpoint itself
    if request.url.path == "/metrics":
        return await call_next(request)
        
    try:
        # Wrap the entire request in a 15-second max timeout
        return await asyncio.wait_for(call_next(request), timeout=15.0)
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=504,
            content={"detail": "Gateway Timeout: The request exceeded the 15-second global time limit."}
        )

# 4. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok", "version": "2.1.0"}

app.include_router(scan.router, dependencies=[Depends(require_api_key)])
app.include_router(history.router, dependencies=[Depends(require_api_key)])
app.include_router(report.router, dependencies=[Depends(require_api_key)])
# app.include_router(anonymized_scan_router, dependencies=[Depends(require_api_key)])
app.include_router(qr_scan_router, dependencies=[Depends(require_api_key)])
app.include_router(platform_router, dependencies=[Depends(require_api_key)])
app.include_router(document_scan_router, dependencies=[Depends(require_api_key)])
app.include_router(visual_scan_router, dependencies=[Depends(require_api_key)])
app.include_router(agentic_scan_router, dependencies=[Depends(require_api_key)])
app.include_router(trust_seals_router, dependencies=[Depends(require_api_key)])

from app.api.routes.prompt_scan import router as prompt_scan_router
app.include_router(prompt_scan_router, dependencies=[Depends(require_api_key)])
