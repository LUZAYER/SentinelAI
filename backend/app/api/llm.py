"""
LLM API

Endpoints for Ollama model management, configuration, and interactive evidence-grounded
explanation generation.
"""

import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.detection_result import DetectionResult
from backend.app.services.llm.ollama_service import OllamaService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/llm", tags=["LLM"])


class ExplanationRequest(BaseModel):
    analysis_id: Optional[int] = Field(None, description="Existing analysis ID to explain")
    analysis_type: Optional[str] = Field("phishing", description="Threat modality: deepfake, document, phishing, scam, malware")
    risk_score: Optional[float] = Field(65.0, description="Risk score 0-100")
    severity: Optional[str] = Field("HIGH", description="Severity label")
    indicators: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Forensic indicators")
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Extracted evidence dictionary")
    persona: Optional[str] = Field("soc", description="Target persona: executive, soc, or legal")


@router.get("/models")
async def list_models(current_user: User = Depends(get_current_user)):
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
        return {
            "models": [
                {"name": settings.OLLAMA_MODEL, "is_active": True, "status": "configured_offline"}
            ],
            "active_model": settings.OLLAMA_MODEL,
            "ollama_url": settings.OLLAMA_BASE_URL,
            "note": "Ollama host offline. Heuristic fallback reasoning active."
        }
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


@router.post("/generate")
async def generate_explanation(
    payload: ExplanationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate an evidence-grounded AI forensic explanation.
    Can explain an existing analysis from DB or synthesize explanation from raw indicators.
    """
    analysis_type = payload.analysis_type or "phishing"
    risk_data = {
        "overall_score": payload.risk_score,
        "severity": payload.severity,
        "confidence": 0.85,
    }
    detection_result = {
        "status": "completed",
        "risk_score": payload.risk_score,
        "indicators": payload.indicators,
        "evidence": payload.evidence,
        "technical_details": {},
    }

    # If analysis_id provided, load real evidence from database
    if payload.analysis_id:
        analysis = (await db.execute(select(Analysis).where(Analysis.id == payload.analysis_id))).scalars().first()
        if analysis:
            analysis_type = analysis.analysis_type
            risk = (await db.execute(select(RiskAssessment).where(RiskAssessment.analysis_id == analysis.id))).scalars().first()
            if risk:
                risk_data["overall_score"] = risk.overall_score
                risk_data["severity"] = risk.severity
                risk_data["confidence"] = risk.confidence
            det = (await db.execute(select(DetectionResult).where(DetectionResult.analysis_id == analysis.id))).scalars().first()
            if det:
                detection_result["indicators"] = det.indicators or {}
                detection_result["evidence"] = det.evidence or {}
                detection_result["technical_details"] = det.technical_details or {}

    service = OllamaService()
    explanation = service.explain_analysis(analysis_type, detection_result, risk_data)

    # Adjust perspective based on persona if needed
    if payload.persona == "executive":
        explanation["summary"] = f"Executive Risk Summary: {explanation.get('summary', '')}"
    elif payload.persona == "legal":
        explanation["summary"] = f"Evidentiary Chain & Compliance Note: {explanation.get('summary', '')}"

    return {
        "analysis_type": analysis_type,
        "persona": payload.persona,
        "explanation": explanation,
        "risk_data": risk_data,
        "source": "ollama" if explanation.get("model") != "fallback_generator" else "deterministic_heuristics",
    }
