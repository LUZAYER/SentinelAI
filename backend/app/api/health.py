"""
Health Check API

System health endpoint checking database, Redis, and Ollama connectivity.
"""

import logging

import httpx
import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Check system health: database, Redis, and Ollama connectivity."""
    health = {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "services": {},
    }

    # Database check
    try:
        await db.execute(text("SELECT 1"))
        health["services"]["database"] = {"status": "connected", "type": "postgresql"}
    except Exception as e:
        health["services"]["database"] = {"status": "error", "error": str(e)}
        health["status"] = "degraded"

    # Redis check
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
        health["services"]["redis"] = {"status": "connected"}
    except Exception as e:
        health["services"]["redis"] = {"status": "error", "error": str(e)}
        health["status"] = "degraded"

    # Ollama check
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/version")
            if resp.status_code == 200:
                version_data = resp.json()
                health["services"]["ollama"] = {
                    "status": "connected",
                    "version": version_data.get("version", "unknown"),
                    "configured_model": settings.OLLAMA_MODEL,
                }
            else:
                health["services"]["ollama"] = {"status": "error", "http_status": resp.status_code}
                health["status"] = "degraded"
    except Exception as e:
        health["services"]["ollama"] = {"status": "unavailable", "error": str(e)}
        health["status"] = "degraded"

    return health
