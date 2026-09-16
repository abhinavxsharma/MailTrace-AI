"""
Tests for Phase 6 infrastructure risk scoring and calibrated evidence fusion.
"""

import pytest

from app.detection.risk_fusion import fuse_evidence, MAX_INFRASTRUCTURE
from app.schemas.risk import RiskClassification
from app.schemas.verification import AuthenticationSchema, AuthStatus, IdentitySchema


def test_infrastructure_score_cap():
    """Verify infrastructure contribution never exceeds 15 points."""
    ai_pred = {"label": "BENIGN", "confidence": 0.5}
    features = {}
    infra_intel = {
        "source_ip": "198.51.100.42",
        "suspicious_signals": [
            "Sender domain has no valid Mail Exchanger (MX) records",
            "Sender domain does not resolve in public DNS",
            "Observed fast-flux IP pattern",
            "Suspicious dynamic DNS provider",
            "Extra signal beyond cap",
        ],
    }

    res = fuse_evidence(
        ai_prediction=ai_pred,
        features=features,
        infrastructure_intelligence=infra_intel,
    )

    assert res["infrastructure_score"] <= MAX_INFRASTRUCTURE
    assert res["infrastructure_score"] == 15
    assert res["risk_contributions"]["infrastructure"] == 15


def test_infrastructure_score_zero_when_no_signals():
    """Verify infrastructure contribution is 0 when no suspicious signals exist."""
    ai_pred = {"label": "BENIGN", "confidence": 0.5}
    features = {}
    infra_intel = {
        "source_ip": "198.51.100.42",
        "suspicious_signals": [],
    }

    res = fuse_evidence(
        ai_prediction=ai_pred,
        features=features,
        infrastructure_intelligence=infra_intel,
    )

    assert res["infrastructure_score"] == 0
    assert res["risk_contributions"]["infrastructure"] == 0


def test_infrastructure_forensic_explanations():
    """Verify forensic statements for GeoIP and RDAP use non-attributive wording."""
    ai_pred = {"label": "BENIGN", "confidence": 0.5}
    features = {}
    infra_intel = {
        "source_ip": "198.51.100.42",
        "geoip": {
            "198.51.100.42": {"status": "AVAILABLE", "country": "Germany", "city": "Frankfurt"},
        },
        "rdap": {
            "198.51.100.42": {"status": "AVAILABLE", "organization": "Example Cloud AS1234"},
        },
        "suspicious_signals": ["Sender domain has no valid Mail Exchanger (MX) records"],
    }

    res = fuse_evidence(
        ai_prediction=ai_pred,
        features=features,
        observed_source_ip="198.51.100.42",
        infrastructure_intelligence=infra_intel,
    )

    exps = res["explanations"]
    assert any("Observed Source Infrastructure: 198.51.100.42" in e for e in exps)
    assert any("IP Geolocation indicates registration in Germany (Frankfurt)" in e for e in exps)
    assert any("Observed Network / Registration Information: Example Cloud AS1234" in e for e in exps)
    assert any("Infrastructure Evidence" in e for e in exps)
    # Ensure strict forensic restraint
    assert not any("attacker location" in e.lower() for e in exps)
