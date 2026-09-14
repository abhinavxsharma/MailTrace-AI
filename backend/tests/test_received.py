"""
Tests for Received header parsing and MTA hop reconstruction.
"""

from app.forensics.received import (
    parse_received_header,
    analyze_received_chain,
    is_valid_ipv4,
)


def test_is_valid_ipv4():
    """Verify IPv4 validation helper."""
    assert is_valid_ipv4("198.51.100.42") is True
    assert is_valid_ipv4("10.0.0.1") is True
    assert is_valid_ipv4("999.999.999.999") is False
    assert is_valid_ipv4("not-an-ip") is False


def test_parse_single_received_header():
    """Verify parsing of standard RFC 5322 Received header."""
    header = (
        "from relay-07.cloud (198.51.100.42) by mail.acme.edu with ESMTPS id ABC123; "
        "Thu, 03 Sep 2026 15:49:12 +0530"
    )
    parsed = parse_received_header(header)
    assert parsed["from_host"] == "relay-07.cloud"
    assert parsed["by_host"] == "mail.acme.edu"
    assert parsed["source_ip"] == "198.51.100.42"
    assert "Thu, 03 Sep 2026" in parsed["timestamp"]


def test_analyze_received_chain_identifies_observed_source():
    """Verify analyzing Received chain correctly extracts the observed source IP."""
    headers = [
        # Top hop (recipient boundary)
        "from relay-07.cloud (198.51.100.42) by mail.acme.edu with ESMTPS; Thu, 03 Sep 2026 15:49:12 +0530",
        # Bottom hop (internal or earlier relay)
        "from billing-node (10.20.14.8) by relay-07.cloud with ESMTPS; Thu, 03 Sep 2026 10:48:59 +0000",
    ]
    result = analyze_received_chain(headers)
    assert result["hop_count"] == 2
    assert len(result["hops"]) == 2
    # 198.51.100.42 is the public relay IP (observed source infrastructure)
    assert result["observed_source_ip"] == "198.51.100.42"


def test_empty_received_chain():
    """Verify handling when no Received headers exist."""
    result = analyze_received_chain([])
    assert result["hop_count"] == 0
    assert result["hops"] == []
    assert result["observed_source_ip"] is None
