"""
MAILTRACE AI - MaxMind GeoIP Geolocation Intelligence Service.
Extracts coarse IP geolocation and ASN metadata when a local MMDB database is configured.
Note: Forensics safety rule - IP geolocation reflects observed routing infrastructure,
never physical human location or personal attribution.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from app.config import settings
from app.forensics.indicators import classify_ip

logger = logging.getLogger(__name__)


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP is in RFC 1918 private or loopback range."""
    c = classify_ip(ip_str.strip())
    return c in ("private", "loopback")


def lookup_geoip(
    ip_str: str,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform local GeoIP lookup using MaxMind MMDB database if configured.
    Returns structured geolocation metadata.
    If database is unavailable, returns {"status": "UNAVAILABLE"} safely without crashing.
    """
    clean_ip = (ip_str or "").strip()
    if not clean_ip:
        return {
            "status": "NOT_FOUND",
            "ip": ip_str,
            "error": "Empty IP address",
        }

    # Internal / private IP
    if _is_private_ip(clean_ip):
        return {
            "status": "NOT_FOUND",
            "ip": clean_ip,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "organization": "Internal / RFC 1918 Network",
            "description": "Observed Source Infrastructure: Internal private IP (no public geolocation)",
        }

    # Locate MMDB database path
    configured_path = db_path if db_path is not None else settings.MAXMIND_DB_PATH
    if not configured_path:
        return {
            "status": "UNAVAILABLE",
            "ip": clean_ip,
            "description": "IP Geolocation: Database unavailable (not configured)",
        }

    mmdb_file = Path(configured_path)
    if not mmdb_file.exists():
        return {
            "status": "UNAVAILABLE",
            "ip": clean_ip,
            "error": f"MMDB database file not found at {configured_path}",
            "description": "IP Geolocation: Database unavailable (file not found)",
        }

    try:
        import geoip2.database
        import geoip2.errors

        with geoip2.database.Reader(str(mmdb_file)) as reader:
            try:
                # Try city database first, falls back to country
                response = reader.city(clean_ip)
                country_name = response.country.name
                country_code = response.country.iso_code
                city_name = response.city.name
                subdiv = response.subdivisions.most_specific.name if response.subdivisions else None
                lat = response.location.latitude
                lon = response.location.longitude

                return {
                    "status": "AVAILABLE",
                    "ip": clean_ip,
                    "country": country_name,
                    "country_code": country_code,
                    "region": subdiv,
                    "city": city_name,
                    "latitude": lat,
                    "longitude": lon,
                    "asn": None,
                    "organization": None,
                    "description": f"IP Geolocation: Observed registration in {country_name or 'Unknown'} ({city_name or 'Unknown'})",
                }
            except geoip2.errors.AddressNotFoundError:
                return {
                    "status": "NOT_FOUND",
                    "ip": clean_ip,
                    "description": "IP Geolocation: Address not found in database",
                }

    except ImportError:
        logger.warning("geoip2 library not installed")
        return {
            "status": "UNAVAILABLE",
            "ip": clean_ip,
            "description": "IP Geolocation: geoip2 library unavailable",
        }
    except Exception as e:
        logger.warning(f"GeoIP resolution error for {clean_ip}: {e}")
        return {
            "status": "UNAVAILABLE",
            "ip": clean_ip,
            "error": str(e),
            "description": "IP Geolocation: Lookup failed",
        }
