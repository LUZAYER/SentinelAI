"""
Analysis Schemas

Request/response models for analysis CRUD operations.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AnalysisCreate(BaseModel):
    """Request to create a new analysis.
    File uploads are handled separately via multipart form data.
    """
    analysis_type: str = Field(..., pattern=r"^(deepfake|document|phishing|scam|malware)$")
    title: str | None = Field(None, max_length=500)
    # For URL-based inputs
    url: str | None = None
    # For text-based inputs
    text_content: str | None = None


class DetectionResultResponse(BaseModel):
    """Detection result from a single detector."""
    id: int
    detector_type: str
    status: str
    risk_score: float
    confidence: float
    indicators: dict
    evidence: dict
    technical_details: dict
    limitations: list
    processing_time_seconds: float | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RiskAssessmentResponse(BaseModel):
    """Aggregated risk assessment."""
    overall_score: float
    severity: str
    confidence: float
    combined_evidence: dict
    high_risk_indicators: list
    scoring_breakdown: dict

    model_config = {"from_attributes": True}


class LLMExplanationResponse(BaseModel):
    """LLM-generated explanation."""
    model_name: str
    explanation: str
    summary: str
    recommendations: list
    risk_explanation: str
    processing_time_seconds: float | None

    model_config = {"from_attributes": True}


class AnalysisInputResponse(BaseModel):
    """Analysis input details."""
    url: str | None
    text_content: str | None
    original_filename: str | None

    model_config = {"from_attributes": True}


class AnalysisResponse(BaseModel):
    """Full analysis response with all related data."""
    id: int
    user_id: int
    analysis_type: str
    input_type: str
    status: str
    title: str | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None

    # Related data (populated when available)
    analysis_input: AnalysisInputResponse | None = None
    detection_results: list[DetectionResultResponse] = []
    risk_assessment: RiskAssessmentResponse | None = None
    llm_explanation: LLMExplanationResponse | None = None

    model_config = {"from_attributes": True}


class AnalysisListResponse(BaseModel):
    """Paginated list of analyses."""
    items: list[AnalysisResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class AnalysisStats(BaseModel):
    """Dashboard statistics."""
    total_analyses: int = 0
    completed_analyses: int = 0
    high_risk_count: int = 0
    analyses_by_type: dict[str, int] = {}
    analyses_by_status: dict[str, int] = {}
    recent_analyses: list[AnalysisResponse] = []
    risk_distribution: dict[str, int] = {}
