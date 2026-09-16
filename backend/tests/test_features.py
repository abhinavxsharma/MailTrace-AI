"""
Tests for Phase 5 forensic linguistic and structural feature extraction.
"""

import pytest
from app.detection.features import extract_forensic_features
from app.schemas.email import EmailSchema
from app.schemas.indicator import IndicatorSchema
from app.schemas.verification import IdentitySchema


def test_extract_features_bec_content():
    """Verify all critical BEC signals (urgency, financial, authority, secrecy, link) are extracted."""
    email = EmailSchema(
        subject="URGENT: Change Vendor Bank Account Today",
        body_text=(
            "Hi Accounts Team, This is an urgent request from the CFO. "
            "We have changed our banking partner and the beneficiary account for the "
            "outstanding vendor invoice must be updated today. Please process the transfer immediately "
            "using the secure finance portal. Please do not call to confirm this request as I am in a meeting. "
            "Regards, CFO Acme Finance"
        ),
    )
    indicators = [
        IndicatorSchema(type="url", value="https://secure-acme-login.example/verify-invoice"),
        IndicatorSchema(type="domain", value="secure-acme-login.example"),
    ]
    identity = IdentitySchema(reply_to_mismatch=True, return_path_mismatch=True)

    feats = extract_forensic_features(email, indicators=indicators, identity=identity)

    assert feats["urgency_detected"] is True
    assert feats["financial_detected"] is True
    assert feats["credentials_detected"] is True
    assert feats["authority_detected"] is True
    assert feats["secrecy_detected"] is True
    assert feats["request_action_detected"] is True
    assert feats["suspicious_links_detected"] is True
    assert feats["phishing_phrases_detected"] is True
    assert feats["reply_to_mismatch"] is True
    assert feats["return_path_mismatch"] is True
    assert feats["url_count"] == 1
    assert feats["domain_count"] == 1

    # Verify human-readable explanations are generated
    assert len(feats["explanations"]) >= 5
    assert any("urgent" in exp.lower() for exp in feats["explanations"])
    assert any("financial" in exp.lower() for exp in feats["explanations"])
    assert any("cfo" in exp.lower() for exp in feats["explanations"])


def test_extract_features_benign_content():
    """Verify benign content does not trigger false positive phishing/urgency cues."""
    email = EmailSchema(
        subject="Project Status Discussion",
        body_text="Hi team, attached are the design notes for review during tomorrow's sync.",
    )
    feats = extract_forensic_features(email)

    assert feats["urgency_detected"] is False
    assert feats["financial_detected"] is False
    assert feats["credentials_detected"] is False
    assert feats["authority_detected"] is False
    assert feats["secrecy_detected"] is False
    assert feats["reply_to_mismatch"] is False
    assert feats["url_count"] == 0


def test_extract_features_empty_content():
    """Verify empty/missing email content is handled safely."""
    email = EmailSchema()
    feats = extract_forensic_features(email)

    assert feats["urgency_detected"] is False
    assert feats["financial_detected"] is False
    assert feats["url_count"] == 0
    assert len(feats["explanations"]) == 0


def test_extract_features_html_only():
    """Verify HTML-only content is parsed for linguistic signals."""
    email = EmailSchema(
        subject="Action Required",
        body_html="<p>Please <b>update payment details</b> immediately for the pending <i>invoice</i>.</p>",
    )
    feats = extract_forensic_features(email)

    assert feats["urgency_detected"] is True
    assert feats["financial_detected"] is True
    assert feats["request_action_detected"] is True
