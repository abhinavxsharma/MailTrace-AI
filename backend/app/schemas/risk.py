"""
Risk fusion and explainable AI (XAI) schema contracts.
Enforces calibrated 0-100 risk thresholds and evidence contribution factors.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class RiskClassification(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def get_risk_classification(score: int) -> RiskClassification:
    """Map a 0-100 score to calibrated risk classification."""
    if score < 0 or score > 100:
        raise ValueError("Risk score must be between 0 and 100")
    if score <= 39:
        return RiskClassification.LOW
    elif score <= 69:
        return RiskClassification.MEDIUM
    elif score <= 84:
        return RiskClassification.HIGH
    else:
        return RiskClassification.CRITICAL


class RiskDimensions(BaseModel):
    ai_threat: float = 0.0
    authentication: float = 0.0
    identity_consistency: float = 0.0
    url_risk: float = 0.0
    infrastructure_risk: float = 0.0
    campaign_risk: float = 0.0
    bec_risk: float = 0.0


class RiskReason(BaseModel):
    rule: str
    points: str  # e.g., "+18"
    description: str


class RiskAssessment(BaseModel):
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    classification: Optional[RiskClassification] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    dimensions: RiskDimensions = Field(default_factory=RiskDimensions)
    reasons: List[RiskReason] = Field(default_factory=list)

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, v: Optional[RiskClassification]) -> Optional[RiskClassification]:
        if v is not None and v not in RiskClassification:
            raise ValueError(f"Invalid classification: {v}. Must be one of {[e.value for e in RiskClassification]}")
        return v


class CaseAnalyzeResponse(BaseModel):
    case_id: str
    status: str = "ANALYZED"
    ai_prediction: dict = Field(default_factory=dict)
    ai_confidence: float = 0.0
    extracted_features: dict = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskClassification
    risk_contributions: dict = Field(default_factory=dict)
    infrastructure: dict = Field(default_factory=dict)
    dns: dict = Field(default_factory=dict)
    rdap: dict = Field(default_factory=dict)
    geoip: dict = Field(default_factory=dict)
    infrastructure_score: int = 0
    graph: dict = Field(default_factory=dict)
    correlation: dict = Field(default_factory=dict)
    timeline: List[dict] = Field(default_factory=list)
    campaign_score: int = 0
    explanations: List[str] = Field(default_factory=list)
