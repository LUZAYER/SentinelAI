"""
Report Model

Stores generated security reports. Each completed analysis produces a report
containing the full analysis results in a structured format suitable for
professional review, academic demonstration, or incident triage.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # Structured report content
    content: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Path to generated PDF file (relative to storage)
    pdf_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Report format version
    format_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="report")

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, analysis_id={self.analysis_id})>"
