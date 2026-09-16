"""
Tests for Phase 5 ThreatClassifier and Dataset 3 Hugging Face model integration.
"""

import pytest
from app.detection.classifier import (
    ThreatClassifier,
    get_classifier,
    strip_html_tags,
    resolve_model_path,
)
from app.schemas.detection import DetectionSchema


def test_strip_html_tags():
    """Verify HTML stripping cleans script tags and HTML elements."""
    html = "<html><head><script>bad();</script></head><body><p>Hello <b>World</b></p></body></html>"
    cleaned = strip_html_tags(html)
    assert "bad()" not in cleaned
    assert "Hello World" in cleaned


def test_resolve_model_path():
    """Verify model path resolution."""
    path = resolve_model_path("ml/models/dataset3_v1.0.0")
    assert path.exists()
    assert (path / "config.json").exists()
    assert (path / "model.safetensors").exists()


def test_classifier_singleton():
    """Verify get_classifier returns singleton instance."""
    clf1 = get_classifier()
    clf2 = get_classifier()
    assert clf1 is clf2
    assert clf1.model_name == "dataset3_v1.0.0"


def test_classifier_inference_malicious_bec():
    """Verify malicious BEC text produces high threat score."""
    clf = get_classifier()
    subject = "URGENT: Change Vendor Bank Account Today"
    body = (
        "Hi Accounts Team, This is an urgent request from the CFO. "
        "We have changed our banking partner and the beneficiary account for the "
        "outstanding vendor invoice must be updated today. Please process the transfer immediately."
    )
    result: DetectionSchema = clf.classify_email(subject=subject, body_text=body)
    assert result.model == "dataset3_v1.0.0"
    assert result.ai_threat_score is not None
    assert result.ai_threat_score >= 0.85
    assert result.bec_score >= 0.85
    assert len(result.signals) > 0
    assert result.signals[0].name == "Transformer Threat Detection"


def test_classifier_inference_benign():
    """Verify benign text produces low threat score."""
    clf = get_classifier()
    subject = "Weekly Project Update"
    body = "Hi team, please find attached the weekly sprint summary and action items."
    result: DetectionSchema = clf.classify_email(subject=subject, body_text=body)
    assert result.model == "dataset3_v1.0.0"
    assert result.ai_threat_score is not None
    assert result.ai_threat_score < 0.20
    assert result.bec_score == 0.0


def test_classifier_inference_empty():
    """Verify empty input returns benign default schema safely."""
    clf = get_classifier()
    result: DetectionSchema = clf.classify_email(subject="", body_text="")
    assert result.model == "dataset3_v1.0.0"
    assert result.ai_threat_score == 0.0
    assert result.bec_score == 0.0


def test_classifier_inference_html_only():
    """Verify HTML-only email body is extracted and classified."""
    clf = get_classifier()
    html = "<p>Urgent: wire funds immediately to account 123456789</p>"
    result: DetectionSchema = clf.classify_email(subject="Payment details", body_html=html)
    assert result.ai_threat_score is not None


def test_classifier_graceful_fallback_on_invalid_path():
    """Verify that an invalid model path gracefully returns UNAVAILABLE status without crashing."""
    bad_classifier = ThreatClassifier(model_path="nonexistent/path/to/model")
    res = bad_classifier.predict("Hello test")
    assert res["status"] == "MODEL_UNAVAILABLE"
    assert res["threat_score"] is None

    schema_res = bad_classifier.classify_email(subject="Test", body_text="Hello")
    assert schema_res.ai_threat_score is None
    assert "unavailable" in schema_res.model
    assert len(schema_res.signals) > 0
