"""
Analysis API

Endpoints for submitting content for analysis and retrieving results.
"""

import hashlib
import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.analysis import Analysis
from backend.app.models.analysis_input import AnalysisInput
from backend.app.models.uploaded_file import UploadedFile
from backend.app.models.user import User
from backend.app.schemas.analysis import AnalysisCreate, AnalysisResponse
from backend.app.workers.analysis_worker import run_analysis_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])


def validate_file_extension(filename: str, analysis_type: str) -> bool:
    """Validate file extension against allowed types for the analysis."""
    ext = os.path.splitext(filename)[1].lower()
    
    if analysis_type == "deepfake":
        allowed = settings.allowed_image_extensions + settings.allowed_video_extensions + settings.allowed_audio_extensions
    elif analysis_type == "document":
        allowed = settings.allowed_document_extensions + settings.allowed_image_extensions
    elif analysis_type == "malware":
        allowed = settings.allowed_image_extensions + settings.allowed_video_extensions + settings.allowed_audio_extensions + settings.allowed_document_extensions + settings.allowed_archive_extensions + [".exe", ".dll", ".sh", ".bin"]
    else:
        return False
        
    return ext in allowed


@router.post("/upload", response_model=AnalysisResponse)
async def analyze_file(
    analysis_type: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit a file for analysis."""
    if analysis_type not in ["deepfake", "document", "malware"]:
        raise HTTPException(status_code=400, detail="Invalid analysis type for file upload")

    if not file.filename or not validate_file_extension(file.filename, analysis_type):
        raise HTTPException(status_code=400, detail="Unsupported file format for this analysis type")

    # Ensure upload directory exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

    # Read and hash file
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large. Max {settings.MAX_UPLOAD_SIZE_MB}MB")

    file_hash = hashlib.sha256(content).hexdigest()
    
    # Generate unique stored name to prevent collisions
    ext = os.path.splitext(file.filename)[1].lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(settings.UPLOAD_DIR, stored_name)

    # Save file
    with open(file_path, "wb") as f:
        f.write(content)

    # Create database records
    uploaded_file = UploadedFile(
        filename=file.filename,
        stored_name=stored_name,
        file_size=len(content),
        mime_type=file.content_type or "application/octet-stream",
        sha256=file_hash,
    )
    db.add(uploaded_file)
    await db.flush()

    analysis = Analysis(
        user_id=current_user.id,
        analysis_type=analysis_type,
        input_type="file",
        status="PENDING",
    )
    db.add(analysis)
    await db.flush()

    analysis_input = AnalysisInput(
        analysis_id=analysis.id,
        uploaded_file_id=uploaded_file.id,
        original_filename=file.filename,
    )
    db.add(analysis_input)
    await db.commit()
    await db.refresh(analysis)

    # Dispatch Celery task
    run_analysis_task.delay(analysis.id)

    return analysis


@router.post("/url", response_model=AnalysisResponse)
async def analyze_url(
    payload: AnalysisCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit a URL for analysis."""
    if payload.analysis_type != "phishing":
        raise HTTPException(status_code=400, detail="URL input is only valid for phishing analysis")

    if not payload.url:
        raise HTTPException(status_code=400, detail="URL is required")

    analysis = Analysis(
        user_id=current_user.id,
        analysis_type=payload.analysis_type,
        input_type="url",
        status="PENDING",
    )
    db.add(analysis)
    await db.flush()

    analysis_input = AnalysisInput(
        analysis_id=analysis.id,
        url=str(payload.url),
    )
    db.add(analysis_input)
    await db.commit()
    await db.refresh(analysis)

    # Dispatch Celery task
    run_analysis_task.delay(analysis.id)

    return analysis


@router.post("/text", response_model=AnalysisResponse)
async def analyze_text(
    payload: AnalysisCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit text for analysis."""
    if payload.analysis_type != "scam":
        raise HTTPException(status_code=400, detail="Text input is only valid for scam analysis")

    if not payload.text_content:
        raise HTTPException(status_code=400, detail="Text content is required")

    analysis = Analysis(
        user_id=current_user.id,
        analysis_type=payload.analysis_type,
        input_type="text",
        status="PENDING",
    )
    db.add(analysis)
    await db.flush()

    analysis_input = AnalysisInput(
        analysis_id=analysis.id,
        text_content=payload.text_content,
    )
    db.add(analysis_input)
    await db.commit()
    await db.refresh(analysis)

    # Dispatch Celery task
    run_analysis_task.delay(analysis.id)

    return analysis


@router.get("/stats")
async def get_analysis_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get dashboard statistics for the current user."""
    from backend.app.models.risk_assessment import RiskAssessment
    from sqlalchemy import func
    
    # Total scans
    total_scans = (await db.execute(
        select(func.count()).select_from(Analysis).where(Analysis.user_id == current_user.id)
    )).scalar() or 0
    
    # We need to join Analysis and RiskAssessment
    # Clean (SAFE/LOW)
    clean_count = (await db.execute(
        select(func.count()).select_from(Analysis)
        .join(RiskAssessment, RiskAssessment.analysis_id == Analysis.id)
        .where(Analysis.user_id == current_user.id, RiskAssessment.severity.in_(["SAFE", "LOW"]))
    )).scalar() or 0
    
    # Suspicious (MEDIUM)
    suspicious_count = (await db.execute(
        select(func.count()).select_from(Analysis)
        .join(RiskAssessment, RiskAssessment.analysis_id == Analysis.id)
        .where(Analysis.user_id == current_user.id, RiskAssessment.severity == "MEDIUM")
    )).scalar() or 0
    
    # Malicious (HIGH/CRITICAL)
    malicious_count = (await db.execute(
        select(func.count()).select_from(Analysis)
        .join(RiskAssessment, RiskAssessment.analysis_id == Analysis.id)
        .where(Analysis.user_id == current_user.id, RiskAssessment.severity.in_(["HIGH", "CRITICAL"]))
    )).scalar() or 0
    
    return {
        "totalScans": total_scans,
        "clean": clean_count,
        "suspicious": suspicious_count,
        "malicious": malicious_count
    }


@router.get("", response_model=list[AnalysisResponse])
async def list_analyses(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List recent analyses for the current user."""
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == current_user.id)
        .order_by(desc(Analysis.created_at))
        .offset(offset)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{analysis_id}")
async def get_analysis_status(
    analysis_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the full status and results of a specific analysis."""
    # We return a custom dictionary here because Pydantic models might be too restrictive 
    # for the deeply nested dynamic JSON data in detection_results and risk_assessments
    
    result = await db.execute(
        select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == current_user.id)
    )
    analysis = result.scalars().first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    response = {
        "id": analysis.id,
        "analysis_type": analysis.analysis_type,
        "input_type": analysis.input_type,
        "status": analysis.status,
        "error_message": analysis.error_message,
        "created_at": analysis.created_at,
        "completed_at": analysis.completed_at,
    }
    
    # If completed, fetch related data
    if analysis.status == "COMPLETED":
        # Load related data manually since lazy loading is tricky in async
        from backend.app.models.detection_result import DetectionResult
        from backend.app.models.risk_assessment import RiskAssessment
        from backend.app.models.llm_explanation import LLMExplanation
        from backend.app.models.analysis_input import AnalysisInput
        
        # Get input
        input_res = await db.execute(select(AnalysisInput).where(AnalysisInput.analysis_id == analysis_id))
        inp = input_res.scalars().first()
        if inp:
            response["input"] = {
                "url": inp.url,
                "text_snippet": inp.text_content[:100] + "..." if inp.text_content else None,
            }
            if inp.uploaded_file_id:
                from backend.app.models.uploaded_file import UploadedFile
                file_res = await db.execute(select(UploadedFile).where(UploadedFile.id == inp.uploaded_file_id))
                file_obj = file_res.scalars().first()
                if file_obj:
                    response["input"]["filename"] = file_obj.filename

        # Get detection results
        det_res = await db.execute(select(DetectionResult).where(DetectionResult.analysis_id == analysis_id))
        detection = det_res.scalars().first()
        if detection:
            response["detection"] = {
                "status": detection.status,
                "risk_score": detection.risk_score,
                "confidence": detection.confidence,
                "indicators": detection.indicators,
                "evidence": detection.evidence,
                "technical_details": detection.technical_details,
            }

        # Get risk assessment
        risk_res = await db.execute(select(RiskAssessment).where(RiskAssessment.analysis_id == analysis_id))
        risk = risk_res.scalars().first()
        if risk:
            response["risk"] = {
                "overall_score": risk.overall_score,
                "severity": risk.severity,
            }

        # Get LLM explanation
        llm_res = await db.execute(select(LLMExplanation).where(LLMExplanation.analysis_id == analysis_id))
        llm = llm_res.scalars().first()
        if llm:
            response["explanation"] = {
                "summary": llm.summary,
                "explanation": llm.explanation,
                "recommendations": llm.recommendations,
            }
            
    return response
