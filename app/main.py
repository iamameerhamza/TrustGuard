import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.lifespan import lifespan
from app.core.auth import require_api_key
from app.api.routes import history, report, scan

# Restrict CORS to configured origins (comma-separated), default to Vite dev server.
_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

app = FastAPI(
    title="TrustGuard API",
    description="URL threat intelligence API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

# All feature routers require a valid API key.
app.include_router(scan.router, dependencies=[Depends(require_api_key)])
app.include_router(history.router, dependencies=[Depends(require_api_key)])
app.include_router(report.router, dependencies=[Depends(require_api_key)])
