"""
Unit tests for Authentication-Results parsing, SPF verification, DKIM handling, and DMARC alignment.
"""

from unittest.mock import patch
import pytest
import dns.exception
import dns.resolver

from app.schemas.verification import AuthStatus
from app.forensics.authentication import (
    parse_authentication_results_header,
    verify_spf_dns,
    verify_dkim_signature,
    evaluate_alignment,
    normalize_auth_status,
)
from app.forensics.headers import analyze_identity_consistency


def test_normalize_auth_status():
    """Verify status string mapping to AuthStatus enum."""
    assert normalize_auth_status("pass") == AuthStatus.PASS
    assert normalize_auth_status("PASS") == AuthStatus.PASS
    assert normalize_auth_status("fail") == AuthStatus.FAIL
    assert normalize_auth_status("softfail") == AuthStatus.NEUTRAL
    assert normalize_auth_status("neutral") == AuthStatus.NEUTRAL
    assert normalize_auth_status("none") == AuthStatus.NONE
    assert normalize_auth_status("temperror") == AuthStatus.UNAVAILABLE
    assert normalize_auth_status("unknown") == AuthStatus.UNKNOWN
    assert normalize_auth_status(None) == AuthStatus.UNKNOWN
    assert normalize_auth_status("unrecognized_val") == AuthStatus.UNKNOWN


def test_parse_authentication_results_header_bec():
    """Verify parsing declared header from the authentic BEC fixture."""
    header = (
        "mail.acme.edu; "
        "spf=pass smtp.mailfrom=notify-acme.co; "
        "dkim=pass header.d=notify-acme.co; "
        "dmarc=fail header.from=acme-finance.com"
    )
    parsed = parse_authentication_results_header(header)
    assert parsed["spf"]["status"] == AuthStatus.PASS
    assert parsed["spf"]["domain"] == "notify-acme.co"

    assert parsed["dkim"]["status"] == AuthStatus.PASS
    assert parsed["dkim"]["domain"] == "notify-acme.co"

    assert parsed["dmarc"]["status"] == AuthStatus.FAIL
    assert parsed["dmarc"]["from_domain"] == "acme-finance.com"


def test_parse_authentication_results_missing_and_malformed():
    """Verify parser handles missing and malformed Authentication-Results safely."""
    # None
    assert parse_authentication_results_header(None)["spf"]["status"] == AuthStatus.UNKNOWN
    # Empty string
    assert parse_authentication_results_header("")["dkim"]["status"] == AuthStatus.UNKNOWN
    # Malformed garbage
    garbage = "Something completely unrelated; random=words; no auth tags here"
    parsed = parse_authentication_results_header(garbage)
    assert parsed["spf"]["status"] == AuthStatus.UNKNOWN
    assert parsed["dkim"]["status"] == AuthStatus.UNKNOWN
    assert parsed["dmarc"]["status"] == AuthStatus.UNKNOWN


def test_identity_enhanced_fields():
    """Verify identity consistency analysis reports granular domain and mismatch flags."""
    # 1. Matching domains
    id1 = analyze_identity_consistency(
        from_header="Finance <finance@acme.edu>",
        reply_to_header="finance@acme.edu",
        return_path_header="<finance@acme.edu>",
    )
    assert id1.from_domain == "acme.edu"
    assert id1.reply_to_domain == "acme.edu"
    assert id1.return_path_domain == "acme.edu"
    assert id1.reply_to_mismatch is False
    assert id1.return_path_mismatch is False
    assert id1.mismatch_detected is False

    # 2. Reply-To mismatch only
    id2 = analyze_identity_consistency(
        from_header="CFO <cfo@acme-finance.com>",
        reply_to_header="alert@gmail.com",
        return_path_header="<cfo@acme-finance.com>",
    )
    assert id2.reply_to_mismatch is True
    assert id2.return_path_mismatch is False
    assert id2.mismatch_detected is True

    # 3. Return-Path mismatch only
    id3 = analyze_identity_consistency(
        from_header="CFO <cfo@acme-finance.com>",
        reply_to_header="cfo@acme-finance.com",
        return_path_header="<bounce@thirdparty.com>",
    )
    assert id3.reply_to_mismatch is False
    assert id3.return_path_mismatch is True
    assert id3.mismatch_detected is True

    # 4. Both mismatches (authentic BEC case)
    id4 = analyze_identity_consistency(
        from_header="CFO <cfo@acme-finance.com>",
        reply_to_header="acme.alert@gmail.com",
        return_path_header="<billing@notify-acme.co>",
    )
    assert id4.reply_to_mismatch is True
    assert id4.return_path_mismatch is True
    assert id4.mismatch_detected is True


class MockTXTRecord:
    def __init__(self, strings):
        self.strings = [s.encode("utf-8") if isinstance(s, str) else s for s in strings]


def test_spf_verification_matching_ip():
    """Verify SPF evaluation when sending IP is explicitly authorized in policy."""
    mock_records = [MockTXTRecord(["v=spf1 ip4:198.51.100.0/24 -all"])]
    with patch("dns.resolver.Resolver.resolve", return_value=mock_records):
        status, details = verify_spf_dns(
            source_ip="198.51.100.42",
            sender_domain="notify-acme.co",
        )
        assert status == AuthStatus.PASS
        assert "matches mechanism 'ip4:198.51.100.0/24'" in details


def test_spf_verification_unauthorized_ip():
    """Verify SPF evaluation fails when sending IP is not authorized."""
    mock_records = [MockTXTRecord(["v=spf1 ip4:192.0.2.0/24 -all"])]
    with patch("dns.resolver.Resolver.resolve", return_value=mock_records):
        status, details = verify_spf_dns(
            source_ip="198.51.100.42",
            sender_domain="notify-acme.co",
        )
        assert status == AuthStatus.FAIL
        assert "-all" in details


def test_spf_verification_no_record():
    """Verify SPF evaluation returns NONE when domain has no SPF policy."""
    with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        status, details = verify_spf_dns(
            source_ip="198.51.100.42",
            sender_domain="nonexistent-domain-404.example",
        )
        assert status == AuthStatus.NONE
        assert "No SPF record found" in details


def test_spf_verification_dns_timeout():
    """Verify SPF evaluation returns UNAVAILABLE when DNS times out."""
    with patch("dns.resolver.Resolver.resolve", side_effect=dns.exception.Timeout):
        status, details = verify_spf_dns(
            source_ip="198.51.100.42",
            sender_domain="timeout.example",
        )
        assert status == AuthStatus.UNAVAILABLE
        assert "timeout" in details.lower()


def test_dkim_verification_missing_signature():
    """Verify DKIM verification returns NONE when raw email lacks DKIM-Signature."""
    raw_no_dkim = b"From: sender@example.com\r\nSubject: No DKIM\r\n\r\nBody text"
    status, domain, selector, details = verify_dkim_signature(raw_no_dkim)
    assert status == AuthStatus.NONE
    assert "No DKIM-Signature header present" in details


def test_dkim_verification_dns_failure():
    """Verify DKIM returns UNAVAILABLE on DNS lookup errors."""
    raw_with_dkim = (
        b"From: test@example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=mail; bh=abc; b=xyz\r\n"
        b"\r\nBody"
    )
    with patch("dkim.verify", side_effect=dns.resolver.NXDOMAIN):
        status, domain, selector, details = verify_dkim_signature(raw_with_dkim)
        assert status == AuthStatus.UNAVAILABLE
        assert "lookup failed" in details.lower()


def test_dmarc_alignment_evaluation():
    """Verify DMARC alignment logic under strict and relaxed modes."""
    # 1. Aligned SPF only (DMARC passes)
    align1, dmarc1, _ = evaluate_alignment(
        from_domain="acme.edu",
        spf_domain="mail.acme.edu",
        dkim_domain="other.com",
        spf_status=AuthStatus.PASS,
        dkim_status=AuthStatus.FAIL,
    )
    assert align1.spf is True
    assert align1.dkim is False
    assert align1.overall is True
    assert dmarc1 == AuthStatus.PASS

    # 2. Aligned DKIM only (DMARC passes)
    align2, dmarc2, _ = evaluate_alignment(
        from_domain="acme.edu",
        spf_domain="thirdparty.com",
        dkim_domain="acme.edu",
        spf_status=AuthStatus.FAIL,
        dkim_status=AuthStatus.PASS,
    )
    assert align2.spf is False
    assert align2.dkim is True
    assert align2.overall is True
    assert dmarc2 == AuthStatus.PASS

    # 3. Neither aligned (DMARC fails even if individual checks were PASS)
    align3, dmarc3, _ = evaluate_alignment(
        from_domain="acme-finance.com",
        spf_domain="notify-acme.co",
        dkim_domain="notify-acme.co",
        spf_status=AuthStatus.PASS,
        dkim_status=AuthStatus.PASS,
    )
    assert align3.spf is False
    assert align3.dkim is False
    assert align3.overall is False
    assert dmarc3 == AuthStatus.FAIL

    # 4. Strict vs Relaxed alignment test
    align_relaxed, _, _ = evaluate_alignment(
        from_domain="acme.edu",
        spf_domain="sub.acme.edu",
        dkim_domain=None,
        spf_status=AuthStatus.PASS,
        dkim_status=AuthStatus.NONE,
        strict_spf=False,
    )
    assert align_relaxed.spf is True

    align_strict, _, _ = evaluate_alignment(
        from_domain="acme.edu",
        spf_domain="sub.acme.edu",
        dkim_domain=None,
        spf_status=AuthStatus.PASS,
        dkim_status=AuthStatus.NONE,
        strict_spf=True,
    )
    assert align_strict.spf is False
