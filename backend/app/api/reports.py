"""
Reports API

Endpoints for generating and retrieving analysis reports.
"""

import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from backend.app.core.database import get_db
from backend.app.core.security import get_current_user
from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.detection_result import DetectionResult
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.llm_explanation import LLMExplanation
from backend.app.models.analysis_input import AnalysisInput

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("")
async def get_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all completed reports for the current user."""
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == current_user.id, Analysis.status == "COMPLETED")
        .order_by(desc(Analysis.completed_at))
    )
    
    reports = []
    for analysis in result.scalars().all():
        inp = (await db.execute(select(AnalysisInput).where(AnalysisInput.analysis_id == analysis.id))).scalars().first()
        risk = (await db.execute(select(RiskAssessment).where(RiskAssessment.analysis_id == analysis.id))).scalars().first()
        
        reports.append({
            "id": analysis.id,
            "type": analysis.analysis_type,
            "date": analysis.completed_at,
            "input": inp.url if inp and inp.url else (inp.uploaded_file_id if inp and inp.uploaded_file_id else "Text"),
            "risk_score": risk.overall_score if risk else 0,
            "severity": risk.severity if risk else "UNKNOWN",
        })
        
    return reports


@router.get("/{analysis_id}/pdf")
async def get_report_pdf(
    analysis_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a PDF report for a completed analysis."""
    result = await db.execute(
        select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == current_user.id)
    )
    analysis = result.scalars().first()
    
    if not analysis or analysis.status != "COMPLETED":
        raise HTTPException(status_code=404, detail="Completed analysis not found")

    # Fetch related data
    inp = (await db.execute(select(AnalysisInput).where(AnalysisInput.analysis_id == analysis_id))).scalars().first()
    risk = (await db.execute(select(RiskAssessment).where(RiskAssessment.analysis_id == analysis_id))).scalars().first()
    llm = (await db.execute(select(LLMExplanation).where(LLMExplanation.analysis_id == analysis_id))).scalars().first()

    # Generate PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(f"SentinelAI Forensic Report", styles['Title']))
    elements.append(Paragraph(f"Analysis ID: {analysis.id}", styles['Normal']))
    elements.append(Paragraph(f"Date: {analysis.completed_at.strftime('%Y-%m-%d %H:%M:%S') if analysis.completed_at else 'Unknown'}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Input Details
    elements.append(Paragraph("Input Information", styles['Heading2']))
    if inp:
        input_data = [
            ["Type", analysis.analysis_type.upper()],
            ["Method", analysis.input_type.upper()]
        ]
        if inp.url: input_data.append(["URL", inp.url])
        t = Table(input_data, colWidths=[100, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.whitesmoke),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
    elements.append(Spacer(1, 12))

    # Risk Assessment
    if risk:
        elements.append(Paragraph("Risk Assessment", styles['Heading2']))
        severity_color = colors.green if risk.severity in ["SAFE", "LOW"] else colors.orange if risk.severity == "MEDIUM" else colors.red
        elements.append(Paragraph(f"Severity: <font color='{severity_color}'><b>{risk.severity}</b></font> (Score: {risk.overall_score}/100)", styles['Normal']))
        elements.append(Spacer(1, 12))

    # Summary
    if llm:
        elements.append(Paragraph("Executive Summary", styles['Heading2']))
        elements.append(Paragraph(llm.summary, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        elements.append(Paragraph("Detailed Findings", styles['Heading2']))
        elements.append(Paragraph(llm.explanation, styles['Normal']))
        elements.append(Spacer(1, 12))
        
        if llm.recommendations:
            elements.append(Paragraph("Recommendations", styles['Heading2']))
            for rec in llm.recommendations:
                elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 12))

    doc.build(elements)
    buffer.seek(0)
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=SentinelAI_Report_{analysis.id}.pdf"}
    )


@router.get("/{analysis_id}/json")
async def get_report_json(
    analysis_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export the full analysis as JSON."""
    result = await db.execute(
        select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == current_user.id)
    )
    analysis = result.scalars().first()
    
    if not analysis or analysis.status != "COMPLETED":
        raise HTTPException(status_code=404, detail="Completed analysis not found")

    inp = (await db.execute(select(AnalysisInput).where(AnalysisInput.analysis_id == analysis_id))).scalars().first()
    detection = (await db.execute(select(DetectionResult).where(DetectionResult.analysis_id == analysis_id))).scalars().first()
    risk = (await db.execute(select(RiskAssessment).where(RiskAssessment.analysis_id == analysis_id))).scalars().first()
    llm = (await db.execute(select(LLMExplanation).where(LLMExplanation.analysis_id == analysis_id))).scalars().first()

    report_data = {
        "metadata": {
            "id": analysis.id,
            "type": analysis.analysis_type,
            "status": analysis.status,
            "created_at": analysis.created_at.isoformat(),
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        },
        "risk": {
            "score": risk.overall_score if risk else None,
            "severity": risk.severity if risk else None,
        },
        "detection": {
            "indicators": detection.indicators if detection else [],
            "technical_details": detection.technical_details if detection else {},
        },
        "explanation": {
            "summary": llm.summary if llm else None,
            "findings": llm.explanation if llm else None,
            "recommendations": llm.recommendations if llm else [],
        }
    }
    
    return report_data
