"""
Analysis Model

Central record for each analysis job submitted by a user.
Tracks the analysis lifecycle from QUEUED through COMPLETED/FAILED.

Status flow:
    QUEUED → PROCESSING → ANALYZING → GENERATING_REPORT → COMPLETED
                                                        → FAILED
                                                        → CANCELLED
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base

import enum


class AnalysisStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    ANALYZING = "ANALYZING"
    GENERATING_REPORT = "GENERATING_REPORT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AnalysisType(str, enum.Enum):
    DEEPFAKE = "deepfake"
    DOCUMENT = "document"
    PHISHING = "phishing"
    SCAM = "scam"
    MALWARE = "malware"


class InputType(str, enum.Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    URL = "url"
    TEXT = "text"
    FILE = "file"


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    input_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=AnalysisStatus.QUEUED.value, index=True
    )
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user = relationship("User", back_populates="analyses")
    analysis_input = relationship("AnalysisInput", back_populates="analysis", uselist=False, lazy="selectin")
    detection_results = relationship("DetectionResult", back_populates="analysis", lazy="selectin")
    risk_assessment = relationship("RiskAssessment", back_populates="analysis", uselist=False, lazy="selectin")
    llm_explanation = relationship("LLMExplanation", back_populates="analysis", uselist=False, lazy="selectin")
    report = relationship("Report", back_populates="analysis", uselist=False, lazy="selectin")

    def __repr__(self) -> str:
        return f"<Analysis(id={self.id}, type={self.analysis_type}, status={self.status})>"
