"""
Analysis Worker

Celery task that runs the full analysis pipeline:
  1. Update status → PROCESSING
  2. Preprocessing & feature extraction
  3. Run appropriate detector → ANALYZING
  4. Risk aggregation
  5. LLM explanation → GENERATING_REPORT
  6. Report generation → COMPLETED

Uses synchronous SQLAlchemy since Celery workers run in separate processes.
"""

import logging
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.workers.celery_app import celery_app
from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# Synchronous engine for Celery workers (asyncpg doesn't work in sync context)
SYNC_DATABASE_URL = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

try:
    sync_engine = create_engine(SYNC_DATABASE_URL, pool_pre_ping=True)
    SyncSession = sessionmaker(bind=sync_engine)
except Exception as e:
    logger.error(f"Failed to create sync engine: {e}")
    sync_engine = None
    SyncSession = None


def _update_status(session: Session, analysis_id: int, status: str, error: str | None = None):
    """Update analysis status in the database."""
    from backend.app.models.analysis import Analysis
    analysis = session.get(Analysis, analysis_id)
    if analysis:
        analysis.status = status
        analysis.updated_at = datetime.now(timezone.utc)
        if error:
            analysis.error_message = error
        if status == "COMPLETED":
            analysis.completed_at = datetime.now(timezone.utc)
        session.commit()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def run_analysis_task(self, analysis_id: int):
    """Main analysis pipeline task.

    This is dispatched by the Analysis API when a new analysis is created.
    It runs the appropriate detector, aggregates risk, generates LLM explanation,
    and creates the final report.
    """
    if SyncSession is None:
        logger.error("Database not available for worker")
        return {"status": "error", "message": "Database not available"}

    session = SyncSession()

    try:
        from backend.app.models.analysis import Analysis
        from backend.app.models.analysis_input import AnalysisInput
        from backend.app.models.uploaded_file import UploadedFile
        from backend.app.models.detection_result import DetectionResult
        from backend.app.models.risk_assessment import RiskAssessment
        from backend.app.models.llm_explanation import LLMExplanation
        from backend.app.models.report import Report

        analysis = session.get(Analysis, analysis_id)
        if not analysis:
            logger.error(f"Analysis {analysis_id} not found")
            return {"status": "error", "message": "Analysis not found"}

        logger.info(f"Starting analysis pipeline: id={analysis_id}, type={analysis.analysis_type}")

        # --- Step 1: PROCESSING ---
        _update_status(session, analysis_id, "PROCESSING")

        # Get input data
        analysis_input = session.query(AnalysisInput).filter_by(analysis_id=analysis_id).first()
        if not analysis_input:
            _update_status(session, analysis_id, "FAILED", "No input data found")
            return {"status": "error", "message": "No input data"}

        # Get file path if applicable
        file_path = None
        if analysis_input.uploaded_file_id:
            uploaded_file = session.get(UploadedFile, analysis_input.uploaded_file_id)
            if uploaded_file:
                import os
                file_path = os.path.join(os.path.abspath(settings.UPLOAD_DIR), uploaded_file.stored_name)

        # --- Step 2: ANALYZING (run detector) ---
        _update_status(session, analysis_id, "ANALYZING")
        start_time = time.time()

        detection_result_data = _run_detector(
            analysis.analysis_type,
            file_path=file_path,
            url=analysis_input.url,
            text_content=analysis_input.text_content,
        )
        processing_time = time.time() - start_time

        # Save detection result
        detection_result = DetectionResult(
            analysis_id=analysis_id,
            detector_type=analysis.analysis_type,
            status=detection_result_data.get("status", "unknown"),
            risk_score=detection_result_data.get("risk_score", 0),
            confidence=detection_result_data.get("confidence", 0),
            indicators=detection_result_data.get("indicators", {}),
            evidence=detection_result_data.get("evidence", {}),
            technical_details=detection_result_data.get("technical_details", {}),
            limitations=detection_result_data.get("limitations", []),
            processing_time_seconds=processing_time,
        )
        session.add(detection_result)
        session.commit()

        # --- Step 3: Risk Aggregation ---
        risk_data = _aggregate_risk([detection_result_data])
        risk_assessment = RiskAssessment(
            analysis_id=analysis_id,
            overall_score=risk_data["overall_score"],
            severity=risk_data["severity"],
            confidence=risk_data["confidence"],
            combined_evidence=risk_data["combined_evidence"],
            high_risk_indicators=risk_data["high_risk_indicators"],
            scoring_breakdown=risk_data["scoring_breakdown"],
        )
        session.add(risk_assessment)
        session.commit()

        # --- Step 4: LLM Explanation ---
        _update_status(session, analysis_id, "GENERATING_REPORT")

        llm_data = _generate_llm_explanation(
            analysis.analysis_type,
            detection_result_data,
            risk_data,
        )
        llm_explanation = LLMExplanation(
            analysis_id=analysis_id,
            model_name=llm_data.get("model", settings.OLLAMA_MODEL),
            explanation=llm_data.get("explanation", ""),
            summary=llm_data.get("summary", ""),
            recommendations=llm_data.get("recommendations", []),
            risk_explanation=llm_data.get("risk_explanation", ""),
            raw_response=llm_data.get("raw_response"),
            processing_time_seconds=llm_data.get("processing_time"),
        )
        session.add(llm_explanation)
        session.commit()

        # --- Step 5: Generate Report ---
        report_content = _generate_report_content(
            analysis, detection_result_data, risk_data, llm_data
        )
        report = Report(
            analysis_id=analysis_id,
            content=report_content,
            format_version="1.0",
        )
        session.add(report)
        session.commit()

        # --- Step 6: COMPLETED ---
        _update_status(session, analysis_id, "COMPLETED")

        logger.info(f"Analysis completed: id={analysis_id}, risk={risk_data['overall_score']}")
        return {"status": "completed", "analysis_id": analysis_id}

    except Exception as e:
        logger.error(f"Analysis {analysis_id} failed: {e}", exc_info=True)
        _update_status(session, analysis_id, "FAILED", str(e))
        return {"status": "error", "message": str(e)}
    finally:
        session.close()


def _run_detector(analysis_type: str, file_path: str | None = None,
                  url: str | None = None, text_content: str | None = None) -> dict:
    """Dispatch to the appropriate detector based on analysis type.

    This is the integration point for Phase 3 detectors.
    Currently uses baseline implementations.
    """
    if analysis_type == "deepfake":
        from backend.app.detectors.deepfake.detector import DeepfakeDetector
        detector = DeepfakeDetector()
        return detector.analyze(file_path=file_path)
    elif analysis_type == "document":
        from backend.app.detectors.document.detector import DocumentDetector
        detector = DocumentDetector()
        return detector.analyze(file_path=file_path)
    elif analysis_type == "phishing":
        from backend.app.detectors.phishing.detector import PhishingDetector
        detector = PhishingDetector()
        return detector.analyze(url=url)
    elif analysis_type == "scam":
        from backend.app.detectors.scam.detector import ScamDetector
        detector = ScamDetector()
        return detector.analyze(text_content=text_content)
    elif analysis_type == "malware":
        from backend.app.detectors.malware.detector import MalwareDetector
        detector = MalwareDetector()
        return detector.analyze(file_path=file_path)
    else:
        return {
            "status": "unknown",
            "risk_score": 0,
            "confidence": 0,
            "indicators": {},
            "evidence": {},
            "limitations": [f"Unknown analysis type: {analysis_type}"],
        }


def _aggregate_risk(detection_results: list[dict]) -> dict:
    """Aggregate risk from multiple detection results.

    Scoring methodology:
    - Each detector contributes a risk_score (0-100) and confidence (0-1).
    - The overall score is the confidence-weighted average of risk scores.
    - Severity is determined by thresholds:
        LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100).
    - High-risk indicators are any indicators with risk_score > 60.
    """
    if not detection_results:
        return {
            "overall_score": 0, "severity": "UNKNOWN", "confidence": 0,
            "combined_evidence": {}, "high_risk_indicators": [],
            "scoring_breakdown": {},
        }

    total_weighted_score = 0
    total_confidence = 0
    combined_evidence = {}
    high_risk_indicators = []
    scoring_breakdown = {}

    for i, result in enumerate(detection_results):
        score = result.get("risk_score", 0)
        confidence = result.get("confidence", 0)
        detector = result.get("detector_type", f"detector_{i}")

        weighted = score * confidence
        total_weighted_score += weighted
        total_confidence += confidence

        scoring_breakdown[detector] = {
            "risk_score": score,
            "confidence": confidence,
            "weighted_contribution": weighted,
        }

        # Combine evidence
        evidence = result.get("evidence", {})
        combined_evidence[detector] = evidence

        # Extract high-risk indicators
        indicators = result.get("indicators", {})
        if score > 60:
            high_risk_indicators.append({
                "detector": detector,
                "risk_score": score,
                "key_indicators": indicators,
            })

    # Calculate overall score
    overall_score = total_weighted_score / total_confidence if total_confidence > 0 else 0
    overall_confidence = total_confidence / len(detection_results) if detection_results else 0

    # Determine severity
    if overall_score <= 25:
        severity = "LOW"
    elif overall_score <= 50:
        severity = "MEDIUM"
    elif overall_score <= 75:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {
        "overall_score": round(overall_score, 2),
        "severity": severity,
        "confidence": round(overall_confidence, 4),
        "combined_evidence": combined_evidence,
        "high_risk_indicators": high_risk_indicators,
        "scoring_breakdown": scoring_breakdown,
    }


def _generate_llm_explanation(analysis_type: str, detection_result: dict, risk_data: dict) -> dict:
    """Generate LLM explanation using Ollama.

    The LLM receives structured evidence and produces human-readable
    explanation and recommendations. It does NOT generate detection results.
    """
    try:
        from backend.app.services.llm.ollama_service import OllamaService
        ollama = OllamaService()
        return ollama.explain_analysis(analysis_type, detection_result, risk_data)
    except Exception as e:
        logger.warning(f"LLM explanation failed: {e}. Using fallback.")
        return _fallback_explanation(analysis_type, detection_result, risk_data)


def _fallback_explanation(analysis_type: str, detection_result: dict, risk_data: dict) -> dict:
    """Fallback explanation when Ollama is unavailable."""
    severity = risk_data.get("severity", "UNKNOWN")
    score = risk_data.get("overall_score", 0)

    return {
        "model": "fallback",
        "explanation": (
            f"This {analysis_type} analysis has been completed with an overall risk score of "
            f"{score}/100 ({severity} severity). The detection pipeline identified the indicators "
            f"listed in the evidence section. Please review the detailed findings below."
        ),
        "summary": f"{analysis_type.capitalize()} analysis completed with {severity} severity.",
        "recommendations": [
            "Review the detailed evidence and indicators provided by the detection pipeline.",
            "Cross-reference findings with other sources if available.",
            f"{'Exercise caution with this content.' if score > 50 else 'No immediate action required based on current findings.'}",
        ],
        "risk_explanation": f"The risk score of {score}/100 indicates {severity.lower()} risk level.",
        "raw_response": None,
        "processing_time": 0,
    }


def _generate_report_content(analysis, detection_result: dict, risk_data: dict, llm_data: dict) -> dict:
    """Generate structured report content."""
    return {
        "report_version": "1.0",
        "analysis_id": analysis.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_type": analysis.analysis_type,
        "input_type": analysis.input_type,
        "executive_summary": llm_data.get("summary", ""),
        "risk_assessment": {
            "overall_score": risk_data.get("overall_score", 0),
            "severity": risk_data.get("severity", "UNKNOWN"),
            "confidence": risk_data.get("confidence", 0),
        },
        "detection_findings": {
            "status": detection_result.get("status", "unknown"),
            "risk_score": detection_result.get("risk_score", 0),
            "confidence": detection_result.get("confidence", 0),
            "indicators": detection_result.get("indicators", {}),
        },
        "evidence": detection_result.get("evidence", {}),
        "ai_explanation": llm_data.get("explanation", ""),
        "recommendations": llm_data.get("recommendations", []),
        "technical_details": detection_result.get("technical_details", {}),
        "limitations": detection_result.get("limitations", []),
    }
