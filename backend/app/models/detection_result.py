"""
DetectionResult Model

Stores the output from each detector module. Multiple DetectionResults
can be associated with a single Analysis (e.g., if multiple detectors run).

The indicators and evidence fields store structured JSON data specific
to each detector type.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Which detector produced this result
    detector_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Overall status: clean, suspicious, malicious, unknown
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown")

    # Risk score: 0-100
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Confidence: 0.0 - 1.0
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Structured evidence and indicators (JSONB for PostgreSQL)
    indicators: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    technical_details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    limitations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Optional: processing duration in seconds
    processing_time_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="detection_results")

    def __repr__(self) -> str:
        return (
            f"<DetectionResult(id={self.id}, detector={self.detector_type}, "
            f"risk={self.risk_score}, confidence={self.confidence})>"
        )
