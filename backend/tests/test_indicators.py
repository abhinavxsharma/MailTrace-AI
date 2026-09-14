"""
Tests for IOC indicator extraction (URLs, domains, IPs) from email artifacts.
"""

from app.forensics.indicators import (
    extract_indicators,
    classify_ip,
    clean_domain,
)


def test_classify_ip():
    """Verify IP classification without external requests."""
    assert classify_ip("198.51.100.42") == "public"
    assert classify_ip("10.0.0.1") == "private"
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("240.0.0.1") == "reserved"
    assert classify_ip("invalid-ip") == "invalid"


def test_clean_domain():
    """Verify domain sanitization."""
    assert clean_domain("<notify-acme.co>") == "notify-acme.co"
    assert clean_domain("example.com:8080") == "example.com"
    assert clean_domain("  acme-finance.com.  ") == "acme-finance.com"


def test_extract_indicators_from_bec_scenario():
    """Verify IOC extraction on synthetic BEC content."""
    subject = "URGENT: Change Vendor Bank Account Today"
    body_html = '<p>Please update payment at: <a href="https://secure-acme-login.example/verify-invoice">Link</a></p>'
    raw_headers = {
        "From": "CFO <cfo@acme-finance.com>",
        "Reply-To": "acme.invoice.alert@gmail.com",
        "Return-Path": "<billing@notify-acme.co>",
        "Received": "from relay-07.cloud (198.51.100.42) by mail.acme.edu",
    }

    indicators = extract_indicators(
        subject=subject,
        body_text="",
        body_html=body_html,
        raw_headers=raw_headers,
    )

    types = {ind.type for ind in indicators}
    assert "url" in types
    assert "domain" in types
    assert "ip" in types

    values = {ind.value for ind in indicators}
    assert "https://secure-acme-login.example/verify-invoice" in values
    assert "secure-acme-login.example" in values
    assert "acme-finance.com" in values
    assert "gmail.com" in values
    assert "notify-acme.co" in values
    assert "198.51.100.42" in values


def test_indicators_deduplication():
    """Verify identical indicators across body and headers are deduplicated by (type, value, source)."""
    text = "Visit https://test.example/login and again https://test.example/login"
    indicators = extract_indicators(body_text=text)
    urls = [ind.value for ind in indicators if ind.type == "url"]
    assert urls.count("https://test.example/login") == 1
