"""
Canonical top-level AnalysisResult and CaseDetailResponse schemas.
This is the unified contract between backend, forensics, AI/ML, threat intel, and frontend.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.case import CaseStatus
from app.schemas.email import EmailSchema
from app.schemas.verification import AuthenticationSchema, IdentitySchema
from app.schemas.indicator import IndicatorSchema
from app.schemas.infrastructure import InfrastructureSchema
from app.schemas.detection import DetectionSchema
from app.schemas.risk import RiskClassification, RiskDimensions, RiskReason
from app.schemas.graph import GraphResponse


class AnalysisResult(BaseModel):
    case_id: str
    status: CaseStatus = CaseStatus.UPLOADED
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    classification: Optional[RiskClassification] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    email: EmailSchema = Field(default_factory=EmailSchema)
    authentication: AuthenticationSchema = Field(default_factory=AuthenticationSchema)
    identity: IdentitySchema = Field(default_factory=IdentitySchema)
    indicators: List[IndicatorSchema] = Field(default_factory=list)
    infrastructure: InfrastructureSchema = Field(default_factory=InfrastructureSchema)
    detection: Optional[DetectionSchema] = None
    risk_dimensions: RiskDimensions = Field(default_factory=RiskDimensions)
    reasons: List[RiskReason] = Field(default_factory=list)
    graph: GraphResponse = Field(default_factory=GraphResponse)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# CaseDetailResponse aliases AnalysisResult for case endpoint responses
CaseDetailResponse = AnalysisResult
