"""
AuditLog Model

Records significant actions for security auditing and compliance.
Every sensitive operation (login, analysis submission, report generation,
admin actions) is logged with user, action, resource, and details.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Action performed: LOGIN, REGISTER, ANALYSIS_CREATED, REPORT_GENERATED, etc.
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Resource type affected: user, analysis, report, settings, etc.
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Resource ID affected
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Additional details (JSON)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Client IP address
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # User agent
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"
