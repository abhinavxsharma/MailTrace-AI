"""
MAILTRACE AI - Cross-Case Campaign Correlation Schemas.
"""

from typing import Any, Dict, List
from pydantic import BaseModel, Field


class CorrelationResponse(BaseModel):
    related_case_ids: List[str] = Field(default_factory=list, description="List of related case numbers")
    shared_indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Shared indicators with related cases")
    relationship_strength: str = Field("NONE", description="Deterministic relationship strength: NONE, LOW, MEDIUM, HIGH")
    correlation_reasons: List[str] = Field(default_factory=list, description="Forensic reasoning statements")
    campaign_score: int = Field(0, ge=0, le=10, description="Campaign risk score contribution (0-10)")
