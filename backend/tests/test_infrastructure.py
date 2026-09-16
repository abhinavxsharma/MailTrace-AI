"""
Tests for Phase 6 infrastructure enrichment orchestrator.
"""

from unittest.mock import patch
import pytest

from app.intelligence.infrastructure import enrich_indicators
from app.schemas.indicator import IndicatorSchema


def test_enrich_indicators_deduplication():
    """Verify indicator deduplication and normalization across domains and IPs."""
    indicators = [
        IndicatorSchema(type="domain", value="example.com"),
        IndicatorSchema(type="domain", value="EXAMPLE.COM."),
        IndicatorSchema(type="url", value="https://example.com/login"),
        IndicatorSchema(type="ip", value="198.51.100.42"),
        IndicatorSchema(type="ip", value="198.51.100.42"),
    ]

    with patch("app.intelligence.infrastructure.resolve_dns_records") as mock_dns, \
         patch("app.intelligence.infrastructure.lookup_rdap") as mock_rdap, \
         patch("app.intelligence.infrastructure.lookup_geoip") as mock_geoip:

        mock_dns.return_value = {"domain": "example.com", "status": "AVAILABLE", "has_mx": True, "records": {}}
        mock_rdap.return_value = {"queried_value": "198.51.100.42", "status": "AVAILABLE", "organization": "Test Org"}
        mock_geoip.return_value = {"status": "UNAVAILABLE", "ip": "198.51.100.42"}

        result = enrich_indicators(indicators=indicators, source_ip="198.51.100.42", sender_domain="example.com")

        assert len(result["domains"]) == 1
        assert result["domains"][0] == "example.com"
        assert len(result["ips"]) == 1
        assert result["ips"][0] == "198.51.100.42"
        assert result["infrastructure_schema"].source_ip == "198.51.100.42"
        assert result["has_valid_mx"] is True


def test_enrich_indicators_suspicious_missing_mx():
    """Verify detection of suspicious sender domain lacking MX records."""
    indicators = [IndicatorSchema(type="domain", value="spoofed-bank.example")]

    with patch("app.intelligence.infrastructure.resolve_dns_records") as mock_dns, \
         patch("app.intelligence.infrastructure.lookup_rdap") as mock_rdap, \
         patch("app.intelligence.infrastructure.lookup_geoip") as mock_geoip:

        mock_dns.return_value = {
            "domain": "spoofed-bank.example",
            "status": "AVAILABLE",
            "has_mx": False,
            "records": {"A": ["1.2.3.4"], "MX": []},
        }
        mock_rdap.return_value = {"status": "NOT_FOUND"}
        mock_geoip.return_value = {"status": "UNAVAILABLE"}

        result = enrich_indicators(indicators=indicators, sender_domain="spoofed-bank.example")
        assert len(result["suspicious_signals"]) > 0
        assert any("no valid Mail Exchanger" in s for s in result["suspicious_signals"])
