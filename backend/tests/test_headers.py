"""
Tests for header extraction, normalization, and identity inconsistency checks.
"""

from app.forensics.headers import (
    analyze_identity_consistency,
    extract_address_and_domain,
    extract_core_headers,
)


def test_extract_address_and_domain():
    """Verify parsing addresses and domains from various RFC 5322 header formats."""
    addr, dom = extract_address_and_domain("CFO <cfo@acme-finance.com>")
    assert addr == "cfo@acme-finance.com"
    assert dom == "acme-finance.com"

    addr, dom = extract_address_and_domain("<billing@notify-acme.co>")
    assert addr == "billing@notify-acme.co"
    assert dom == "notify-acme.co"

    addr, dom = extract_address_and_domain("plain@simple.org")
    assert addr == "plain@simple.org"
    assert dom == "simple.org"

    addr, dom = extract_address_and_domain(None)
    assert addr is None
    assert dom is None


def test_identity_mismatch_reply_to():
    """Verify mismatch detected when Visible From domain differs from Reply-To domain."""
    identity = analyze_identity_consistency(
        from_header="CFO <cfo@acme-finance.com>",
        reply_to_header="acme.invoice.alert@gmail.com",
        return_path_header="<billing@notify-acme.co>",
    )
    assert identity.mismatch_detected is True
    assert "acme-finance.com" in identity.details
    assert "gmail.com" in identity.details
    assert "identity inconsistency" in identity.details.lower()


def test_identity_mismatch_return_path_only():
    """Verify mismatch detected when From domain differs from Return-Path domain."""
    identity = analyze_identity_consistency(
        from_header="Finance <finance@acme.edu>",
        reply_to_header="finance@acme.edu",
        return_path_header="bounce@third-party-relay.com",
    )
    assert identity.mismatch_detected is True
    assert "third-party-relay.com" in identity.details


def test_identity_consistency_matching():
    """Verify no mismatch when From, Reply-To, and Return-Path all align."""
    identity = analyze_identity_consistency(
        from_header="Finance Office <finance@acme.edu>",
        reply_to_header="finance@acme.edu",
        return_path_header="<finance@acme.edu>",
    )
    assert identity.mismatch_detected is False
    assert "consistent" in identity.details.lower()


def test_missing_optional_headers():
    """Verify identity analysis handles missing Reply-To or Return-Path gracefully."""
    identity = analyze_identity_consistency(
        from_header="User <user@example.com>",
        reply_to_header=None,
        return_path_header=None,
    )
    assert identity.mismatch_detected is False


def test_extract_core_headers_preserves_repeated_received():
    """Verify core headers extraction preserves multiple Received hops."""
    raw = {
        "From": "sender@test.com",
        "Subject": "Hello",
        "Received": [
            "from relay1 (192.0.2.1) by mail.test.com",
            "from relay2 (198.51.100.1) by relay1",
        ],
    }
    extracted = extract_core_headers(raw)
    assert extracted["From"] == "sender@test.com"
    assert isinstance(extracted["Received"], list)
    assert len(extracted["Received"]) == 2
