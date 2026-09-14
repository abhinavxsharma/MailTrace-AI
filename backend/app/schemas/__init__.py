"""
Schemas package for MAILTRACE AI.
Exports all shared data contracts.
"""

from app.schemas.case import (
    CaseStatus,
    CaseBase,
    CaseCreate,
    CaseTestCreate,
    CaseTestResponse,
    CaseSummaryResponse,
    CaseUploadEvidence,
    CaseUploadResponse,
)
from app.schemas.email import EmailSchema
from app.schemas.verification import (
    AuthStatus,
    AuthenticationSchema,
    IdentitySchema,
    AlignmentStatus,
    DeclaredAuth,
    VerifiedAuth,
    CaseVerifyResponse,
)
from app.schemas.indicator import IndicatorSchema
from app.schemas.infrastructure import InfrastructureSchema
from app.schemas.detection import DetectionSignal, DetectionSchema
from app.schemas.risk import (
    RiskClassification,
    RiskDimensions,
    RiskReason,
    RiskAssessment,
    get_risk_classification,
)
from app.schemas.graph import (
    GraphNodeData,
    GraphNode,
    GraphEdgeData,
    GraphEdge,
    GraphResponse,
)
from app.schemas.report import ReportSchema
from app.schemas.analysis import AnalysisResult, CaseDetailResponse

__all__ = [
    "CaseStatus",
    "CaseBase",
    "CaseCreate",
    "CaseTestCreate",
    "CaseTestResponse",
    "CaseSummaryResponse",
    "CaseUploadEvidence",
    "CaseUploadResponse",
    "EmailSchema",
    "AuthStatus",
    "AuthenticationSchema",
    "IdentitySchema",
    "AlignmentStatus",
    "DeclaredAuth",
    "VerifiedAuth",
    "CaseVerifyResponse",
    "IndicatorSchema",
    "InfrastructureSchema",
    "DetectionSignal",
    "DetectionSchema",
    "RiskClassification",
    "RiskDimensions",
    "RiskReason",
    "RiskAssessment",
    "get_risk_classification",
    "GraphNodeData",
    "GraphNode",
    "GraphEdgeData",
    "GraphEdge",
    "GraphResponse",
    "ReportSchema",
    "AnalysisResult",
    "CaseDetailResponse",
]
