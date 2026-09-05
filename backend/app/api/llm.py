"""
LLM API

Endpoints for Ollama model management and configuration.
"""

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException

from backend.app.core.config import settings
from backend.app.core.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/llm", tags=["LLM"])


@router.get("/models")
async def list_models(current_user=Depends(get_current_user)):
    """List available Ollama models."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = []
                for m in data.get("models", []):
                    models.append({
                        "name": m.get("name"),
                        "size": m.get("size"),
                        "modified_at": m.get("modified_at"),
                        "details": m.get("details", {}),
                        "is_active": m.get("name", "").startswith(settings.OLLAMA_MODEL),
                    })
                return {
                    "models": models,
                    "active_model": settings.OLLAMA_MODEL,
                    "ollama_url": settings.OLLAMA_BASE_URL,
                }
            else:
                raise HTTPException(status_code=502, detail="Ollama returned an error")
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="Ollama is not available. Ensure Ollama is running.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error connecting to Ollama: {str(e)}")


@router.get("/status")
async def ollama_status():
    """Check Ollama connectivity (no auth required for health monitoring)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/version")
            if resp.status_code == 200:
                return {
                    "status": "connected",
                    "version": resp.json().get("version"),
                    "configured_model": settings.OLLAMA_MODEL,
                }
    except Exception:
        pass

    return {"status": "unavailable", "configured_model": settings.OLLAMA_MODEL}
