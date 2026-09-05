"""
SentinelAI ORM Models Package

Imports all models so Alembic and Base.metadata can discover them.
"""

from backend.app.models.user import User
from backend.app.models.analysis import Analysis
from backend.app.models.analysis_input import AnalysisInput
from backend.app.models.uploaded_file import UploadedFile
from backend.app.models.detection_result import DetectionResult
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.llm_explanation import LLMExplanation
from backend.app.models.report import Report
from backend.app.models.audit_log import AuditLog

__all__ = [
    "User",
    "Analysis",
    "AnalysisInput",
    "UploadedFile",
    "DetectionResult",
    "RiskAssessment",
    "LLMExplanation",
    "Report",
    "AuditLog",
]
