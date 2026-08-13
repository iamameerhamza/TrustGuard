import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.cache import AsyncMemoryRedis, init_cache
from app.core.db import init_db
from app.core.predictor import load_model, stop_observer
from app.core.prompt_predictor import load_prompt_model
from app.core.threat_intel import load_blacklist
from modules.intake.virustotal_client import VirusTotalClient

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic for TrustGuard."""
    logger.info("TrustGuard starting up...")
    init_db()
    load_model()
    load_prompt_model()
    load_blacklist()
    await init_cache()

    app.state.vt_client = VirusTotalClient(
        os.getenv("VIRUSTOTAL_API_KEY", ""),
        AsyncMemoryRedis(),
    )
    
    trusted_domains = set()
    tranco_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "top-1m.csv")
    if os.path.exists(tranco_path):
        try:
            with open(tranco_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    if idx >= 100000:
                        break
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        trusted_domains.add(parts[1].lower())
            logger.info(f"Loaded {len(trusted_domains)} domains into Tranco allowlist")
        except Exception as e:
            logger.error(f"Failed to load Tranco allowlist: {e}")
    else:
        logger.warning(f"Tranco list not found at {tranco_path}. VT allowlist will be empty.")
    app.state.trusted_domains = trusted_domains

    try:
        yield
    finally:
        logger.info("TrustGuard shutting down...")
        vt_client = getattr(app.state, "vt_client", None)
        if vt_client is not None:
            await vt_client.close()
        stop_observer()
