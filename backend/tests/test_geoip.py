"""
Tests for Phase 6 MaxMind GeoIP intelligence service.
"""

from unittest.mock import MagicMock, patch
import pytest

from app.intelligence.geoip import lookup_geoip


def test_geoip_private_ip_handled():
    """Verify internal/private IPs return NOT_FOUND without opening database."""
    res = lookup_geoip("10.10.10.10")
    assert res["status"] == "NOT_FOUND"
    assert "Internal" in res["organization"]


def test_geoip_unconfigured_path():
    """Verify unconfigured database path returns UNAVAILABLE cleanly."""
    res = lookup_geoip("198.51.100.42", db_path="")
    assert res["status"] == "UNAVAILABLE"


def test_geoip_nonexistent_file():
    """Verify nonexistent database file returns UNAVAILABLE cleanly without crashing."""
    res = lookup_geoip("198.51.100.42", db_path="nonexistent/GeoLite2-City.mmdb")
    assert res["status"] == "UNAVAILABLE"


def test_geoip_mock_successful_lookup():
    """Verify structured parsing and forensic wording from GeoIP response."""
    mock_city_resp = MagicMock()
    mock_city_resp.country.name = "Germany"
    mock_city_resp.country.iso_code = "DE"
    mock_city_resp.city.name = "Frankfurt"
    mock_city_resp.subdivisions.most_specific.name = "Hesse"
    mock_city_resp.location.latitude = 50.1109
    mock_city_resp.location.longitude = 8.6821

    mock_reader = MagicMock()
    mock_reader.city.return_value = mock_city_resp
    mock_reader.__enter__.return_value = mock_reader

    with patch("pathlib.Path.exists", return_value=True), patch("geoip2.database.Reader", return_value=mock_reader):
        res = lookup_geoip("198.51.100.42", db_path="mock/GeoLite2-City.mmdb")
        assert res["status"] == "AVAILABLE"
        assert res["country"] == "Germany"
        assert res["country_code"] == "DE"
        assert res["city"] == "Frankfurt"
        assert res["latitude"] == 50.1109
        assert res["longitude"] == 8.6821
        assert "IP Geolocation" in res["description"]
        # Ensure no person-level attribution
        assert "attacker" not in res["description"].lower()


def test_geoip_mock_address_not_found():
    """Verify AddressNotFoundError maps to NOT_FOUND."""
    import geoip2.errors

    mock_reader = MagicMock()
    mock_reader.city.side_effect = geoip2.errors.AddressNotFoundError("IP not found")
    mock_reader.__enter__.return_value = mock_reader

    with patch("pathlib.Path.exists", return_value=True), patch("geoip2.database.Reader", return_value=mock_reader):
        res = lookup_geoip("198.51.100.42", db_path="mock/GeoLite2-City.mmdb")
        assert res["status"] == "NOT_FOUND"
