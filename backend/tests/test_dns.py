"""
Tests for Phase 6 passive DNS intelligence service.
"""

from unittest.mock import MagicMock, patch
import pytest
import dns.exception
import dns.resolver

from app.intelligence.dns import resolve_dns_records


def test_dns_valid_domain_mock():
    """Verify DNS record extraction on a successful mock resolution."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_a = MagicMock()
        mock_a.address = "93.184.216.34"

        mock_mx = MagicMock()
        mock_mx.exchange = "mail.example.com."
        mock_mx.preference = 10

        mock_txt = MagicMock()
        mock_txt.to_text.return_value = '"v=spf1 -all"'

        def side_effect(domain, rtype):
            if rtype == "A":
                return [mock_a]
            elif rtype == "MX":
                return [mock_mx]
            elif rtype == "TXT":
                return [mock_txt]
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = side_effect

        result = resolve_dns_records("example.com")
        assert result["status"] == "AVAILABLE"
        assert result["has_mx"] is True
        assert "93.184.216.34" in result["records"]["A"]
        assert result["records"]["MX"][0]["exchange"] == "mail.example.com"
        assert result["records"]["MX"][0]["preference"] == 10
        assert "v=spf1 -all" in result["records"]["TXT"]


def test_dns_nxdomain_not_found():
    """Verify NXDOMAIN maps to structured NOT_FOUND status."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = resolve_dns_records("definitely-nonexistent-domain.xyz")
        assert result["status"] == "NOT_FOUND"
        assert result["has_mx"] is False


def test_dns_timeout_unavailable():
    """Verify DNS timeout maps to structured UNAVAILABLE status."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.exception.Timeout()
        result = resolve_dns_records("slow-dns.example.com")
        assert result["status"] == "UNAVAILABLE"
        assert "timeout" in (result["error"] or "").lower()


def test_dns_malformed_domain():
    """Verify empty or invalid domain input returns NOT_FOUND safely without crashing."""
    assert resolve_dns_records("")["status"] == "NOT_FOUND"
    assert resolve_dns_records("   ")["status"] == "NOT_FOUND"
    assert resolve_dns_records("invalid_no_dot")["status"] == "NOT_FOUND"


def test_dns_caching():
    """Verify in-memory cache returns cached response without duplicate resolver calls."""
    cache = {}
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_a = MagicMock()
        mock_a.address = "1.2.3.4"
        mock_resolve.return_value = [mock_a]

        res1 = resolve_dns_records("cached.example.com", record_types=["A"], cache=cache)
        res2 = resolve_dns_records("cached.example.com", record_types=["A"], cache=cache)

        assert res1 is res2
        assert mock_resolve.call_count == 1
