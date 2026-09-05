"""
RiskAssessment Model

Stores the unified risk aggregation result combining all detector outputs.
One per Analysis.

Severity Levels (documented scoring methodology):
    LOW      (0-25):  No significant risk indicators found.
    MEDIUM   (26-50): Some indicators present but low confidence or non-critical.
    HIGH     (51-75): Multiple strong indicators or high-confidence detection.
    CRITICAL (76-100): Strong evidence of threat with high confidence.
    UNKNOWN:          Insufficient data to determine risk level.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # Overall aggregated risk score: 0-100
    overall_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Severity classification
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")

    # Overall confidence (weighted average of detector confidences)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Combined evidence from all detectors
    combined_evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # High-risk indicators identified
    high_risk_indicators: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Scoring breakdown (shows how the score was calculated)
    scoring_breakdown: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="risk_assessment")

    def __repr__(self) -> str:
        return f"<RiskAssessment(id={self.id}, score={self.overall_score}, severity={self.severity})>"
