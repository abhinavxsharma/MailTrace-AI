"""
Tests for Phase 5 explainable risk fusion and calibrated scoring engine.
"""

import pytest
from app.detection.risk_fusion import (
    fuse_evidence,
    MAX_AI_THREAT,
    MAX_IDENTITY,
    MAX_AUTHENTICATION,
    MAX_URL_DOMAIN,
    MAX_INFRASTRUCTURE,
    MAX_CAMPAIGN,
)
from app.schemas.risk import RiskClassification
from app.schemas.verification import AuthenticationSchema, AuthStatus, IdentitySchema


def test_category_caps():
    """Verify maximum contribution limits are strictly enforced."""
    assert MAX_AI_THREAT == 25
    assert MAX_IDENTITY == 20
    assert MAX_AUTHENTICATION == 15
    assert MAX_URL_DOMAIN == 15
    assert MAX_INFRASTRUCTURE == 15
    assert MAX_CAMPAIGN == 10
    assert (
        MAX_AI_THREAT
        + MAX_IDENTITY
        + MAX_AUTHENTICATION
        + MAX_URL_DOMAIN
        + MAX_INFRASTRUCTURE
        + MAX_CAMPAIGN
        == 100
    )


def test_risk_fusion_bec_scenario():
    """Verify high-risk BEC scenario produces expected calibrated score and contributions."""
    ai_pred = {
        "model": "dataset3_v1.0.0",
        "label": "MALICIOUS",
        "threat_score": 0.9998,
        "confidence": 0.9998,
    }
    features = {
        "urgency_detected": True,
        "financial_detected": True,
        "credentials_detected": True,
        "suspicious_links_detected": True,
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
        "url_count": 1,
    }
    auth = AuthenticationSchema(spf=AuthStatus.PASS, dkim=AuthStatus.PASS, dmarc=AuthStatus.FAIL)
    identity = IdentitySchema(reply_to_mismatch=True, return_path_mismatch=True)

    result = fuse_evidence(
        ai_prediction=ai_pred,
        features=features,
        authentication=auth,
        identity=identity,
        observed_source_ip="198.51.100.42",
    )

    score = result["risk_score"]
    level = result["risk_level"]
    contributions = result["risk_contributions"]

    assert score >= 70
    assert level in (RiskClassification.HIGH, RiskClassification.CRITICAL)
    assert contributions["ai_threat"] == 25
    assert contributions["identity"] == 20
    assert contributions["authentication"] == 10
    assert contributions["url_domain"] == 15
    assert contributions["infrastructure"] == 0
    assert contributions["campaign"] == 0

    # Explanations check
    exps = result["explanations"]
    assert any("MALICIOUS" in e for e in exps)
    assert any("Reply-To" in e for e in exps)
    assert any("DMARC" in e for e in exps)
    assert any("Observed Source Infrastructure: 198.51.100.42" in e for e in exps)


def test_risk_fusion_benign_scenario():
    """Verify benign email produces LOW risk score."""
    ai_pred = {
        "model": "dataset3_v1.0.0",
        "label": "BENIGN",
        "threat_score": 0.0002,
        "confidence": 0.9998,
    }
    features = {
        "urgency_detected": False,
        "financial_detected": False,
        "credentials_detected": False,
        "suspicious_links_detected": False,
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
        "url_count": 0,
    }
    auth = AuthenticationSchema(spf=AuthStatus.PASS, dkim=AuthStatus.PASS, dmarc=AuthStatus.PASS)
    identity = IdentitySchema(reply_to_mismatch=False, return_path_mismatch=False)

    result = fuse_evidence(ai_prediction=ai_pred, features=features, authentication=auth, identity=identity)

    assert result["risk_score"] == 0
    assert result["risk_level"] == RiskClassification.LOW
    assert result["risk_contributions"]["ai_threat"] == 0
    assert result["risk_contributions"]["identity"] == 0
    assert result["risk_contributions"]["authentication"] == 0


def test_deterministic_scoring():
    """Verify risk scoring is completely deterministic across runs."""
    ai_pred = {"model": "dataset3_v1.0.0", "label": "MALICIOUS", "threat_score": 0.85, "confidence": 0.85}
    features = {"reply_to_mismatch": True, "return_path_mismatch": False, "suspicious_links_detected": True}
    auth = AuthenticationSchema(dmarc=AuthStatus.FAIL)

    res1 = fuse_evidence(ai_pred, features, auth)
    res2 = fuse_evidence(ai_pred, features, auth)

    assert res1["risk_score"] == res2["risk_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert res1["risk_contributions"] == res2["risk_contributions"]


def test_risk_score_clamped_to_100():
    """Verify that even in an extreme scenario, score does not exceed 100."""
    ai_pred = {"model": "dataset3_v1.0.0", "label": "MALICIOUS", "threat_score": 1.0, "confidence": 1.0}
    features = {
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
        "suspicious_links_detected": True,
        "credentials_detected": True,
        "url_count": 5,
    }
    auth = AuthenticationSchema(spf=AuthStatus.FAIL, dkim=AuthStatus.FAIL, dmarc=AuthStatus.FAIL)

    result = fuse_evidence(ai_pred, features, auth)
    assert result["risk_score"] <= 100
    assert result["risk_score"] >= 0
