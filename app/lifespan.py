import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.db import init_db
from app.core.predictor import load_model, stop_observer
from app.core.threat_intel import load_blacklist

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic for TrustGuard."""
    logger.info("TrustGuard starting up...")
    init_db()
    load_model()
    load_blacklist()
    yield
    logger.info("TrustGuard shutting down...")
    stop_observer()
