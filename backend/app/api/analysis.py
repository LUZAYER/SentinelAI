"""
Analysis API

Endpoints for creating, listing, and viewing analyses.
Supports file upload via multipart form data and text/URL input via JSON.
"""

import logging
import os
import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.user import User
from backend.app.models.analysis import Analysis, AnalysisStatus, AnalysisType
from backend.app.models.analysis_input import AnalysisInput
from backend.app.models.uploaded_file import UploadedFile
from backend.app.models.detection_result import DetectionResult
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.analysis import (
    AnalysisResponse,
    AnalysisListResponse,
    AnalysisStats,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])


def _sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    # Remove path separators and null bytes
    name = os.path.basename(filename)
    name = name.replace("\x00", "")
    # Limit length
    if len(name) > 255:
        name = name[:255]
    return name


def _get_input_type(analysis_type: str, file: UploadFile | None, url: str | None) -> str:
    """Determine the input type based on analysis type and provided data."""
    if analysis_type == "phishing":
        return "url"
    if analysis_type == "scam":
        return "text"
    if file:
        ext = os.path.splitext(file.filename or "")[1].lower()
        if ext in settings.image_extensions:
            return "image"
        elif ext in settings.video_extensions:
            return "video"
        elif ext in settings.audio_extensions:
            return "audio"
        elif ext in settings.document_extensions:
            return "document"
        else:
            return "file"
    if url:
        return "url"
    return "text"


@router.post("", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def create_analysis(
    request: Request,
    analysis_type: str = Form(...),
    title: str | None = Form(None),
    url: str | None = Form(None),
    text_content: str | None = Form(None),
    file: UploadFile | None = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new analysis.

    Supports three input modes:
    1. File upload (multipart form data)
    2. URL input (for phishing analysis)
    3. Text input (for scam/social engineering analysis)
    """
    # Validate analysis type
    valid_types = {"deepfake", "document", "phishing", "scam", "malware"}
    if analysis_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid analysis type. Must be one of: {', '.join(valid_types)}",
        )

    # Validate input
    if analysis_type in ("deepfake", "document", "malware") and not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{analysis_type} analysis requires a file upload",
        )
    if analysis_type == "phishing" and not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phishing analysis requires a URL",
        )
    if analysis_type == "scam" and not text_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scam analysis requires text content",
        )

    input_type = _get_input_type(analysis_type, file, url)

    # Handle file upload
    uploaded_file_record = None
    original_filename = None
    if file:
        original_filename = _sanitize_filename(file.filename or "upload")
        ext = os.path.splitext(original_filename)[1].lower()

        # Validate extension
        if ext not in settings.allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '{ext}' is not allowed",
            )

        # Read file content
        content = await file.read()

        # Validate file size
        if len(content) > settings.max_upload_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB",
            )

        # MIME type detection using python-magic
        try:
            import magic
            detected_mime = magic.from_buffer(content, mime=True)
        except Exception:
            detected_mime = file.content_type or "application/octet-stream"

        # SHA-256 hash
        sha256 = hashlib.sha256(content).hexdigest()

        # Store file with UUID name
        stored_name = f"{uuid.uuid4().hex}{ext}"
        upload_dir = os.path.abspath(settings.UPLOAD_DIR)
        os.makedirs(upload_dir, exist_ok=True)
        storage_path = os.path.join(upload_dir, stored_name)

        with open(storage_path, "wb") as f:
            f.write(content)

        uploaded_file_record = UploadedFile(
            original_name=original_filename,
            stored_name=stored_name,
            mime_type=detected_mime,
            file_extension=ext,
            sha256=sha256,
            file_size=len(content),
            storage_path=stored_name,
        )
        db.add(uploaded_file_record)
        await db.flush()

    # Create analysis record
    analysis = Analysis(
        user_id=current_user.id,
        analysis_type=analysis_type,
        input_type=input_type,
        status=AnalysisStatus.QUEUED.value,
        title=title or f"{analysis_type.capitalize()} Analysis - {original_filename or url or 'text input'}",
    )
    db.add(analysis)
    await db.flush()

    # Create analysis input
    analysis_input = AnalysisInput(
        analysis_id=analysis.id,
        uploaded_file_id=uploaded_file_record.id if uploaded_file_record else None,
        url=url,
        text_content=text_content,
        original_filename=original_filename,
    )
    db.add(analysis_input)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="ANALYSIS_CREATED",
        resource_type="analysis",
        resource_id=str(analysis.id),
        details={"analysis_type": analysis_type, "input_type": input_type},
        ip_address=request.client.host if request.client else None,
    )
    db.add(audit)

    await db.flush()

    # Dispatch to background worker
    try:
        from backend.app.workers.analysis_worker import run_analysis_task
        task = run_analysis_task.delay(analysis.id)
        analysis.celery_task_id = task.id
    except Exception as e:
        logger.warning(f"Failed to dispatch analysis to worker: {e}. Will process synchronously later.")

    logger.info(f"Analysis created: id={analysis.id}, type={analysis_type}, user={current_user.id}")

    return AnalysisResponse.model_validate(analysis)


@router.get("", response_model=AnalysisListResponse)
async def list_analyses(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    analysis_type: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List analyses for the current user with pagination and filtering."""
    query = select(Analysis).where(Analysis.user_id == current_user.id)

    if analysis_type:
        query = query.where(Analysis.analysis_type == analysis_type)
    if status_filter:
        query = query.where(Analysis.status == status_filter)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Paginate
    query = query.order_by(desc(Analysis.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    analyses = result.scalars().all()

    total_pages = max(1, (total + per_page - 1) // per_page)

    return AnalysisListResponse(
        items=[AnalysisResponse.model_validate(a) for a in analyses],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )


@router.get("/stats", response_model=AnalysisStats)
async def get_analysis_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get dashboard statistics for the current user."""
    user_filter = Analysis.user_id == current_user.id

    # Total analyses
    total = (await db.execute(
        select(func.count()).where(user_filter)
    )).scalar() or 0

    # Completed
    completed = (await db.execute(
        select(func.count()).where(user_filter, Analysis.status == "COMPLETED")
    )).scalar() or 0

    # By type
    type_rows = (await db.execute(
        select(Analysis.analysis_type, func.count())
        .where(user_filter)
        .group_by(Analysis.analysis_type)
    )).all()
    by_type = {row[0]: row[1] for row in type_rows}

    # By status
    status_rows = (await db.execute(
        select(Analysis.status, func.count())
        .where(user_filter)
        .group_by(Analysis.status)
    )).all()
    by_status = {row[0]: row[1] for row in status_rows}

    # High risk count (risk_score > 75)
    high_risk = (await db.execute(
        select(func.count())
        .select_from(Analysis)
        .join(RiskAssessment)
        .where(user_filter, RiskAssessment.overall_score > 75)
    )).scalar() or 0

    # Risk distribution
    risk_dist_rows = (await db.execute(
        select(RiskAssessment.severity, func.count())
        .select_from(Analysis)
        .join(RiskAssessment)
        .where(user_filter)
        .group_by(RiskAssessment.severity)
    )).all()
    risk_dist = {row[0]: row[1] for row in risk_dist_rows}

    # Recent analyses
    recent_result = await db.execute(
        select(Analysis)
        .where(user_filter)
        .order_by(desc(Analysis.created_at))
        .limit(10)
    )
    recent = [AnalysisResponse.model_validate(a) for a in recent_result.scalars().all()]

    return AnalysisStats(
        total_analyses=total,
        completed_analyses=completed,
        high_risk_count=high_risk,
        analyses_by_type=by_type,
        analyses_by_status=by_status,
        recent_analyses=recent,
        risk_distribution=risk_dist,
    )


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single analysis by ID."""
    result = await db.execute(
        select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == current_user.id)
    )
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    return AnalysisResponse.model_validate(analysis)
