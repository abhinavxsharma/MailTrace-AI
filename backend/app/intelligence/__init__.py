"""
MAILTRACE AI - Infrastructure Intelligence Module.
Provides passive DNS resolution, RDAP registration intelligence, and GeoIP enrichment.
"""

from app.intelligence.dns import resolve_dns_records
from app.intelligence.rdap import lookup_rdap
from app.intelligence.geoip import lookup_geoip
from app.intelligence.infrastructure import enrich_indicators

__all__ = [
    "resolve_dns_records",
    "lookup_rdap",
    "lookup_geoip",
    "enrich_indicators",
]
