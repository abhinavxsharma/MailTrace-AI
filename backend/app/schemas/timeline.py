"""
MAILTRACE AI - Chronological Forensic Timeline Schemas.
"""

from typing import Optional
from pydantic import BaseModel, Field


class TimelineItem(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 or RFC 5322 timestamp of the chronological milestone")
    event: str = Field(..., description="Event name (e.g. EMAIL_RECEIVED, EVIDENCE_PRESERVED, AUTHENTICATION_VERIFIED, etc.)")
    source: str = Field(..., description="Component or forensic header originating the event")
    details: Optional[str] = Field(None, description="Human-readable forensic details or explanation")
