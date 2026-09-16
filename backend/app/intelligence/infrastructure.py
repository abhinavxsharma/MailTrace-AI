"""
MAILTRACE AI - Infrastructure Intelligence Orchestrator Service.
Enriches extracted indicators (IPs, domains) with passive DNS, RDAP, and GeoIP metadata.
Avoids duplicate lookups and compiles structured forensic infrastructure evidence.
"""

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set

from app.intelligence.dns import resolve_dns_records
from app.intelligence.rdap import lookup_rdap
from app.intelligence.geoip import lookup_geoip
from app.schemas.indicator import IndicatorSchema
from app.schemas.infrastructure import InfrastructureSchema

logger = logging.getLogger(__name__)


def _classify_indicator_value(val: str) -> str:
    """Classify whether a string is an IP address or domain name."""
    cleaned = val.strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    try:
        ipaddress.ip_address(cleaned)
        return "ip"
    except ValueError:
        return "domain"


def enrich_indicators(
    indicators: Optional[List[IndicatorSchema]] = None,
    source_ip: Optional[str] = None,
    sender_domain: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enrich extracted IP addresses and domains with passive DNS, RDAP, and GeoIP data.
    Caches lookups within the execution to prevent duplicate queries.
    """
    dns_cache: Dict[str, Any] = {}
    rdap_cache: Dict[str, Any] = {}

    unique_domains: Set[str] = set()
    unique_ips: Set[str] = set()

    if source_ip:
        unique_ips.add(source_ip.strip())

    if sender_domain:
        clean_s = sender_domain.strip().lower().rstrip(".")
        if clean_s and "." in clean_s:
            unique_domains.add(clean_s)

    if indicators:
        for ind in indicators:
            val = ind.value.strip()
            if not val:
                continue
            t = ind.type or _classify_indicator_value(val)
            if t == "ip":
                unique_ips.add(val)
            elif t == "domain":
                clean_d = val.lower().rstrip(".")
                if "." in clean_d and not clean_d.startswith("http"):
                    unique_domains.add(clean_d)
            elif t == "url":
                # Extract domain from URL
                if "://" in val:
                    extracted_d = val.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                    if "." in extracted_d:
                        unique_domains.add(extracted_d.lower().rstrip("."))

    # 1. DNS Resolution for unique domains
    dns_results: Dict[str, Any] = {}
    has_any_mx = False
    dns_statuses: Set[str] = set()

    for dom in sorted(list(unique_domains)):
        dns_res = resolve_dns_records(dom, cache=dns_cache)
        dns_results[dom] = dns_res
        dns_statuses.add(dns_res["status"])
        if dns_res.get("has_mx"):
            has_any_mx = True

    overall_dns_status = "AVAILABLE" if "AVAILABLE" in dns_statuses else (
        "NOT_FOUND" if "NOT_FOUND" in dns_statuses else "UNAVAILABLE"
    ) if dns_statuses else "NOT_FOUND"

    # 2. RDAP Lookups for IPs and primary sender domain
    rdap_results: Dict[str, Any] = {}
    rdap_statuses: Set[str] = set()

    for ip in sorted(list(unique_ips)):
        rdap_res = lookup_rdap(ip, target_type="ip", cache=rdap_cache)
        rdap_results[ip] = rdap_res
        rdap_statuses.add(rdap_res["status"])

    for dom in sorted(list(unique_domains))[:3]:  # Limit domain RDAP to top 3
        rdap_res = lookup_rdap(dom, target_type="domain", cache=rdap_cache)
        rdap_results[dom] = rdap_res
        rdap_statuses.add(rdap_res["status"])

    overall_rdap_status = "AVAILABLE" if "AVAILABLE" in rdap_statuses else (
        "NOT_FOUND" if "NOT_FOUND" in rdap_statuses else "UNAVAILABLE"
    ) if rdap_statuses else "NOT_FOUND"

    # 3. GeoIP Lookups for IPs
    geoip_results: Dict[str, Any] = {}
    geoip_statuses: Set[str] = set()

    for ip in sorted(list(unique_ips)):
        g_res = lookup_geoip(ip)
        geoip_results[ip] = g_res
        geoip_statuses.add(g_res["status"])

    overall_geoip_status = "AVAILABLE" if "AVAILABLE" in geoip_statuses else "UNAVAILABLE"

    # 4. Construct normalized InfrastructureSchema
    src_ip_str = source_ip.strip() if source_ip else (list(unique_ips)[0] if unique_ips else None)
    src_geoip = geoip_results.get(src_ip_str, {}) if src_ip_str else {}
    src_rdap = rdap_results.get(src_ip_str, {}) if src_ip_str else {}

    country = src_geoip.get("country") or src_rdap.get("country")
    city = src_geoip.get("city")
    latitude = src_geoip.get("latitude")
    longitude = src_geoip.get("longitude")
    asn = src_rdap.get("asn")
    organization = src_rdap.get("organization") or src_rdap.get("network_name") or src_rdap.get("registrar")

    infra_schema = InfrastructureSchema(
        source_ip=src_ip_str,
        country=country,
        city=city,
        latitude=latitude,
        longitude=longitude,
        asn=asn,
        organization=organization,
        network_type="public" if (src_ip_str and not src_rdap.get("network_name") == "PRIVATE-NETWORK") else "private",
        rdap_status=overall_rdap_status.lower(),
        dns_status=overall_dns_status.lower(),
        geoip_status=overall_geoip_status.lower(),
    )

    # 5. Detect suspicious infrastructure signals
    suspicious_signals: List[str] = []
    if sender_domain and sender_domain in dns_results:
        sender_dns = dns_results[sender_domain]
        if sender_dns["status"] == "AVAILABLE" and not sender_dns.get("has_mx"):
            suspicious_signals.append(f"Sender domain '{sender_domain}' has no valid Mail Exchanger (MX) records")
        elif sender_dns["status"] == "NOT_FOUND":
            suspicious_signals.append(f"Sender domain '{sender_domain}' does not resolve in public DNS")

    return {
        "source_ip": src_ip_str,
        "domains": sorted(list(unique_domains)),
        "ips": sorted(list(unique_ips)),
        "dns": dns_results,
        "rdap": rdap_results,
        "geoip": geoip_results,
        "infrastructure_schema": infra_schema,
        "dns_status": overall_dns_status,
        "rdap_status": overall_rdap_status,
        "geoip_status": overall_geoip_status,
        "has_valid_mx": has_any_mx,
        "suspicious_signals": suspicious_signals,
    }
