"""
Tests for Phase 6 RDAP registration intelligence service.
"""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from app.intelligence.rdap import lookup_rdap


def test_rdap_private_ip_immediate_filter():
    """Verify private/internal IP addresses are identified locally without network requests."""
    res_10 = lookup_rdap("10.0.4.15")
    assert res_10["status"] == "NOT_FOUND"
    assert "Private Network" in res_10["organization"]

    res_192 = lookup_rdap("192.168.1.1")
    assert res_192["status"] == "NOT_FOUND"

    res_127 = lookup_rdap("127.0.0.1")
    assert res_127["status"] == "NOT_FOUND"


def test_rdap_public_ip_success():
    """Verify structured parsing of successful RDAP response."""
    mock_payload = {
        "name": "CLOUD-INFRA-NET",
        "country": "DE",
        "handle": "AS12345",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cloud Infrastructure GmbH"]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["email", {}, "text", "abuse@cloud-infra.example"]]],
            },
        ],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_payload

    with patch("httpx.Client.get", return_value=mock_resp):
        res = lookup_rdap("198.51.100.42", target_type="ip")
        assert res["status"] == "AVAILABLE"
        assert res["organization"] == "Cloud Infrastructure GmbH"
        assert res["network_name"] == "CLOUD-INFRA-NET"
        assert res["country"] == "DE"
        assert res["abuse_contact"] == "abuse@cloud-infra.example"
        assert "Observed Network / Registration Information" in res["description"]


def test_rdap_not_found():
    """Verify 404 response from RDAP maps to NOT_FOUND."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("httpx.Client.get", return_value=mock_resp):
        res = lookup_rdap("unknown-domain.example")
        assert res["status"] == "NOT_FOUND"


def test_rdap_timeout_unavailable():
    """Verify RDAP timeout maps to UNAVAILABLE status gracefully."""
    with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Timeout")):
        res = lookup_rdap("198.51.100.42")
        assert res["status"] == "UNAVAILABLE"
        assert "timeout" in (res["error"] or "").lower()


def test_rdap_connection_error_unavailable():
    """Verify connection errors map to UNAVAILABLE status without crashing."""
    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Network unreachable")):
        res = lookup_rdap("198.51.100.42")
        assert res["status"] == "UNAVAILABLE"


def test_rdap_caching():
    """Verify caching prevents redundant network lookups."""
    cache = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"name": "CACHED-NET"}

    with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
        res1 = lookup_rdap("198.51.100.42", cache=cache)
        res2 = lookup_rdap("198.51.100.42", cache=cache)

        assert res1 is res2
        assert mock_get.call_count == 1
