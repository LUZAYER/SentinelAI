"""
Reports API

Endpoints for viewing and downloading analysis reports.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.report import Report
from backend.app.schemas.report import ReportResponse, ReportListResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("", response_model=ReportListResponse)
async def list_reports(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all reports for the current user."""
    query = (
        select(Report)
        .join(Analysis)
        .where(Analysis.user_id == current_user.id)
    )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    result = await db.execute(
        query.order_by(desc(Report.generated_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    reports = result.scalars().all()

    items = []
    for r in reports:
        resp = ReportResponse.model_validate(r)
        resp.has_pdf = bool(r.pdf_path)
        items.append(resp)

    return ReportListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single report by ID."""
    result = await db.execute(
        select(Report)
        .join(Analysis)
        .where(Report.id == report_id, Analysis.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    resp = ReportResponse.model_validate(report)
    resp.has_pdf = bool(report.pdf_path)
    return resp


@router.get("/{report_id}/json")
async def download_report_json(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download report as JSON."""
    result = await db.execute(
        select(Report)
        .join(Analysis)
        .where(Report.id == report_id, Analysis.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return JSONResponse(
        content=report.content,
        headers={"Content-Disposition": f"attachment; filename=sentinelai_report_{report_id}.json"},
    )


@router.get("/{report_id}/pdf")
async def download_report_pdf(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download report as PDF."""
    result = await db.execute(
        select(Report)
        .join(Analysis)
        .where(Report.id == report_id, Analysis.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if not report.pdf_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF not yet generated")

    import os
    pdf_full_path = os.path.join(os.path.abspath(settings.UPLOAD_DIR), "reports", report.pdf_path)

    if not os.path.exists(pdf_full_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF file not found")

    return FileResponse(
        pdf_full_path,
        media_type="application/pdf",
        filename=f"sentinelai_report_{report_id}.pdf",
    )
