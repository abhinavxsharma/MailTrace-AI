"""
Tests for Pydantic v2 data contract schemas, validation, and thresholds.
"""

import pytest
from pydantic import ValidationError

from app.schemas.case import CaseStatus
from app.schemas.email import EmailSchema
from app.schemas.verification import AuthStatus, AuthenticationSchema, IdentitySchema
from app.schemas.indicator import IndicatorSchema
from app.schemas.infrastructure import InfrastructureSchema
from app.schemas.detection import DetectionSchema, DetectionSignal
from app.schemas.risk import (
    RiskClassification,
    RiskAssessment,
    RiskDimensions,
    RiskReason,
    get_risk_classification,
)
from app.schemas.graph import GraphResponse, GraphNode, GraphNodeData, GraphEdge, GraphEdgeData
from app.schemas.report import ReportSchema
from app.schemas.analysis import AnalysisResult


def test_schema_valid_instantiations():
    """Verify all contracts can be instantiated with valid defaults."""
    email = EmailSchema(from_address="test@example.com", subject="Test")
    assert email.from_address == "test@example.com"
    assert email.attachment_count == 0

    auth = AuthenticationSchema(spf=AuthStatus.PASS, dkim=AuthStatus.PASS, dmarc=AuthStatus.FAIL)
    assert auth.spf == AuthStatus.PASS
    assert auth.dmarc == AuthStatus.FAIL

    identity = IdentitySchema(from_address="cfo@company.com", reply_to="attacker@gmail.com", mismatch_detected=True)
    assert identity.mismatch_detected is True

    indicator = IndicatorSchema(type="ip", value="198.51.100.42", source="Received")
    assert indicator.type == "ip"

    infra = InfrastructureSchema(source_ip="198.51.100.42", country="Germany")
    assert infra.country == "Germany"

    detection = DetectionSchema(
        ai_threat_score=0.88,
        signals=[DetectionSignal(name="Urgency", contribution="+15", description="Urgent language detected")],
    )
    assert detection.signals[0].contribution == "+15"

    graph = GraphResponse(
        nodes=[GraphNode(data=GraphNodeData(id="n1", label="Test Node", type="domain"))],
        edges=[GraphEdge(data=GraphEdgeData(id="e1", source="n1", target="n2", label="RESOLVES_TO"))],
    )
    assert len(graph.nodes) == 1
    assert len(graph.edges) == 1

    report = ReportSchema(case_id="MT-2026-000001")
    assert report.report_format == "json"


def test_risk_score_valid_bounds():
    """Verify valid risk scores (0 to 100) are accepted."""
    risk_zero = RiskAssessment(risk_score=0, classification=RiskClassification.LOW)
    assert risk_zero.risk_score == 0

    risk_max = RiskAssessment(risk_score=100, classification=RiskClassification.CRITICAL)
    assert risk_max.risk_score == 100

    risk_mid = RiskAssessment(risk_score=75, classification=RiskClassification.HIGH)
    assert risk_mid.risk_score == 75


def test_invalid_risk_score_rejected():
    """Verify risk scores outside 0-100 raise ValidationError."""
    with pytest.raises(ValidationError):
        RiskAssessment(risk_score=-1)

    with pytest.raises(ValidationError):
        RiskAssessment(risk_score=101)

    with pytest.raises(ValidationError):
        AnalysisResult(case_id="MT-2026-000001", risk_score=150)


def test_invalid_classification_rejected():
    """Verify unknown classification values raise ValidationError."""
    with pytest.raises(ValidationError):
        RiskAssessment(classification="EXTREME_DANGER")

    with pytest.raises(ValidationError):
        RiskAssessment(classification="SAFE")


def test_documented_thresholds():
    """Verify mapping adherence to documented 0-39, 40-69, 70-84, 85-100 thresholds."""
    # LOW: 0-39
    assert get_risk_classification(0) == RiskClassification.LOW
    assert get_risk_classification(20) == RiskClassification.LOW
    assert get_risk_classification(39) == RiskClassification.LOW

    # MEDIUM: 40-69
    assert get_risk_classification(40) == RiskClassification.MEDIUM
    assert get_risk_classification(55) == RiskClassification.MEDIUM
    assert get_risk_classification(69) == RiskClassification.MEDIUM

    # HIGH: 70-84
    assert get_risk_classification(70) == RiskClassification.HIGH
    assert get_risk_classification(77) == RiskClassification.HIGH
    assert get_risk_classification(84) == RiskClassification.HIGH

    # CRITICAL: 85-100
    assert get_risk_classification(85) == RiskClassification.CRITICAL
    assert get_risk_classification(91) == RiskClassification.CRITICAL
    assert get_risk_classification(100) == RiskClassification.CRITICAL

    # Out of bounds
    with pytest.raises(ValueError):
        get_risk_classification(-5)
    with pytest.raises(ValueError):
        get_risk_classification(105)


def test_canonical_analysis_result_contract():
    """Verify top-level AnalysisResult contains all required sub-contracts."""
    result = AnalysisResult(case_id="MT-2026-000001", status=CaseStatus.UPLOADED)
    assert result.case_id == "MT-2026-000001"
    assert result.status == CaseStatus.UPLOADED
    assert result.risk_score is None
    assert result.classification is None
    assert result.confidence is None
    assert isinstance(result.email, EmailSchema)
    assert isinstance(result.authentication, AuthenticationSchema)
    assert isinstance(result.identity, IdentitySchema)
    assert isinstance(result.indicators, list)
    assert isinstance(result.infrastructure, InfrastructureSchema)
    assert isinstance(result.risk_dimensions, RiskDimensions)
    assert isinstance(result.reasons, list)
    assert isinstance(result.graph, GraphResponse)
    assert isinstance(result.evidence, dict)
