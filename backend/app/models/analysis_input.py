"""
AnalysisInput Model

Stores the actual input data for an analysis: file reference, URL, or text content.
Exactly one per Analysis.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class AnalysisInput(Base):
    __tablename__ = "analysis_inputs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # For file-based inputs
    uploaded_file_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("uploaded_files.id"), nullable=True
    )

    # For URL-based inputs
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # For text-based inputs
    text_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Original filename (for display; actual file is stored under UUID)
    original_filename: Mapped[str | None] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    analysis = relationship("Analysis", back_populates="analysis_input")
    uploaded_file = relationship("UploadedFile", lazy="selectin")

    def __repr__(self) -> str:
        return f"<AnalysisInput(id={self.id}, analysis_id={self.analysis_id})>"
