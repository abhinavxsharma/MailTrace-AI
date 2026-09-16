"""
Tests for Phase 7 campaign risk scoring and evidence fusion integration.
Verifies category maximum (10 points), conditional scoring (0 when no shared evidence),
and total risk score clamping (0-100).
"""

import pytest

from app.detection.risk_fusion import fuse_evidence
from app.schemas.verification import AuthStatus, AuthenticationSchema, IdentitySchema


def test_campaign_risk_zero_without_correlation():
    """Verify that if campaign_correlation is None or has 0 points, campaign contribution is 0."""
    result = fuse_evidence(
        ai_prediction={"label": "BENIGN", "confidence": 0.9, "threat_score": 0.0},
        features={},
        campaign_correlation=None,
    )
    assert result["campaign_score"] == 0
    assert result["risk_contributions"]["campaign"] == 0

    result2 = fuse_evidence(
        ai_prediction={"label": "BENIGN", "confidence": 0.9, "threat_score": 0.0},
        features={},
        campaign_correlation={
            "campaign_score": 0,
            "related_case_ids": [],
            "shared_indicators": [],
            "correlation_reasons": [],
        },
    )
    assert result2["campaign_score"] == 0
    assert result2["risk_contributions"]["campaign"] == 0


def test_campaign_risk_awarded_with_shared_indicators():
    """Verify campaign points are added when actual cross-case evidence is present."""
    correlation_data = {
        "campaign_score": 8,
        "related_case_ids": ["MT-2026-000002", "MT-2026-000005"],
        "shared_indicators": [
            {"type": "source_ip", "value": "198.51.100.42", "related_case": "MT-2026-000002"},
            {"type": "domain", "value": "invoice-portal.example", "related_case": "MT-2026-000005"},
        ],
        "correlation_reasons": [
            "Potential Campaign Relationship: Shared Observed Source IP '198.51.100.42' observed with case MT-2026-000002.",
            "Potential Campaign Relationship: Shared destination domain 'invoice-portal.example' observed with case MT-2026-000005.",
        ],
    }

    result = fuse_evidence(
        ai_prediction={"label": "MALICIOUS", "confidence": 0.95, "threat_score": 1.0},
        features={"reply_to_mismatch": True},
        campaign_correlation=correlation_data,
    )

    assert result["campaign_score"] == 8
    assert result["risk_contributions"]["campaign"] == 8
    assert any("Potential Campaign Relationship" in exp for exp in result["explanations"])
    assert any(r.rule == "Campaign Correlation" for r in result["reasons"])


def test_campaign_risk_capped_at_maximum_10():
    """Verify campaign contribution never exceeds the 10-point maximum."""
    correlation_data = {
        "campaign_score": 25,  # Excess points passed in
        "related_case_ids": ["MT-2026-000099"],
        "shared_indicators": [{"type": "reply_to", "value": "phish@drop.biz"}],
        "correlation_reasons": ["Potential Campaign Relationship: Shared Reply-To"],
    }

    result = fuse_evidence(
        ai_prediction={"label": "BENIGN", "threat_score": 0.0},
        features={},
        campaign_correlation=correlation_data,
    )

    assert result["campaign_score"] == 10
    assert result["risk_contributions"]["campaign"] == 10


def test_total_risk_score_clamped_with_all_categories_maxed():
    """Verify total score does not exceed 100 even if all 6 categories score their maximums."""
    # AI Threat: 25, Identity: 20, Auth: 15, URL: 15, Infra: 15, Campaign: 10 = 100
    auth = AuthenticationSchema(
        spf=AuthStatus.FAIL,
        dkim=AuthStatus.FAIL,
        dmarc=AuthStatus.FAIL,
        alignment="FAIL",
    )
    features = {
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
        "suspicious_links_detected": True,
        "credentials_detected": True,
        "url_count": 3,
    }
    infra = {
        "suspicious_signals": [
            "Sender domain has no valid Mail Exchanger (MX) records",
            "Observed domain does not resolve to any active IP address",
            "Suspicious cloud hosting infrastructure",
        ]
    }
    campaign = {
        "campaign_score": 10,
        "related_case_ids": ["MT-1"],
        "shared_indicators": [{"type": "source_ip", "value": "1.2.3.4"}],
    }

    result = fuse_evidence(
        ai_prediction={"label": "MALICIOUS", "confidence": 0.99, "threat_score": 1.0},
        features=features,
        authentication=auth,
        observed_source_ip="198.51.100.42",
        infrastructure_intelligence=infra,
        campaign_correlation=campaign,
    )

    assert result["risk_score"] == 100
    contribs = result["risk_contributions"]
    assert contribs["ai_threat"] == 25
    assert contribs["identity"] == 20
    assert contribs["authentication"] == 15
    assert contribs["url_domain"] == 15
    assert contribs["infrastructure"] == 15
    assert contribs["campaign"] == 10
    assert sum(contribs.values()) == 100
