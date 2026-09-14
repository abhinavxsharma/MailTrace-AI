"""
Forensic report metadata schemas.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


def utc_now():
    return datetime.now(timezone.utc)


class ReportSchema(BaseModel):
    case_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    report_format: str = "json"  # "json" or "pdf"
    report_path: Optional[str] = None
