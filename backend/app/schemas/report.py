"""
Report Schemas

Request/response models for report operations.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ReportResponse(BaseModel):
    """Report metadata response."""
    id: int
    analysis_id: int
    format_version: str
    generated_at: datetime
    has_pdf: bool = False
    content: dict

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    """Paginated list of reports."""
    items: list[ReportResponse]
    total: int
    page: int
    per_page: int
