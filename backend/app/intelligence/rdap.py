"""
MAILTRACE AI - RDAP Registration Intelligence Service.
Queries public Registration Data Access Protocol (RDAP) endpoints for IP and domain registration data.
Note: Registration ownership describes observed network routing, NOT attacker identity.
"""

import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional
import httpx

from app.forensics.indicators import classify_ip

logger = logging.getLogger(__name__)

DEFAULT_RDAP_TIMEOUT = 5.0
RDAP_BASE_URL = "https://rdap.org"


def _is_private_or_internal(ip_str: str) -> bool:
    """Check if an IP address is RFC 1918 private or loopback."""
    c = classify_ip(ip_str.strip())
    return c in ("private", "loopback")


def _extract_abuse_email(entities: List[Dict[str, Any]]) -> Optional[str]:
    """Extract abuse contact email from RDAP entity hierarchy."""
    if not isinstance(entities, list):
        return None
    for entity in entities:
        roles = entity.get("roles", [])
        if "abuse" in roles:
            # Check vcardArray
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if len(item) > 3 and item[0] == "email":
                        return str(item[3])
        # Recursively inspect sub-entities
        sub = entity.get("entities", [])
        if sub:
            found = _extract_abuse_email(sub)
            if found:
                return found
    return None


def _extract_organization(data: Dict[str, Any]) -> Optional[str]:
    """Extract organization or entity name from RDAP payload."""
    entities = data.get("entities", [])
    if isinstance(entities, list):
        for ent in entities:
            roles = ent.get("roles", [])
            if any(r in roles for r in ["registrant", "administrative", "registrar"]):
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) > 3 and item[0] in ("fn", "org"):
                            return str(item[3])

    # Fallback to top-level network name if entity org not present
    if data.get("name"):
        return str(data["name"])

    return None


def lookup_rdap(
    target: str,
    target_type: Optional[str] = None,
    cache: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_RDAP_TIMEOUT,
) -> Dict[str, Any]:
    """
    Perform safe RDAP registration lookup for an IP address or domain.
    Never treats RDAP ownership as human attacker identity.
    Returns structured data with status: AVAILABLE, UNAVAILABLE, or NOT_FOUND.
    """
    clean_target = (target or "").strip().lower()
    if not clean_target:
        return {
            "queried_value": target,
            "status": "NOT_FOUND",
            "type": target_type or "unknown",
            "error": "Empty target value",
        }

    # Check cache
    if cache is not None and clean_target in cache:
        return cache[clean_target]

    # Classify type if not provided
    is_ip = False
    try:
        ipaddress.ip_address(clean_target)
        is_ip = True
    except ValueError:
        is_ip = False

    actual_type = target_type or ("ip" if is_ip else "domain")

    # Handle private / internal IP without network calls
    if actual_type == "ip" and _is_private_or_internal(clean_target):
        res = {
            "queried_value": clean_target,
            "type": "ip",
            "status": "NOT_FOUND",
            "organization": "Internal / RFC 1918 Private Network",
            "network_name": "PRIVATE-NETWORK",
            "country": None,
            "asn": None,
            "abuse_contact": None,
            "source": "Local Filter",
            "description": "Observed Network / Registration Information: Internal private IP address",
        }
        if cache is not None:
            cache[clean_target] = res
        return res

    # Construct public RDAP URL
    endpoint = f"{RDAP_BASE_URL}/{actual_type}/{clean_target}"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(endpoint, headers={"Accept": "application/rdap+json, application/json"})

            if resp.status_code == 200:
                data = resp.json()
                org = _extract_organization(data)
                abuse = _extract_abuse_email(data.get("entities", []))
                net_name = data.get("name") or org
                country = data.get("country")
                handle = data.get("handle")

                res = {
                    "queried_value": clean_target,
                    "type": actual_type,
                    "status": "AVAILABLE",
                    "registrar": data.get("port43") or org,
                    "network_name": net_name,
                    "organization": org,
                    "country": country,
                    "asn": handle if (handle and handle.upper().startswith("AS")) else None,
                    "abuse_contact": abuse,
                    "source": "RDAP Bootstrap",
                    "description": f"Observed Network / Registration Information: {org or net_name or clean_target}",
                }
            elif resp.status_code == 404:
                res = {
                    "queried_value": clean_target,
                    "type": actual_type,
                    "status": "NOT_FOUND",
                    "error": f"RDAP record not found for {clean_target}",
                    "description": "Observed Network / Registration Information: Record not found",
                }
            else:
                res = {
                    "queried_value": clean_target,
                    "type": actual_type,
                    "status": "UNAVAILABLE",
                    "error": f"RDAP service responded with HTTP {resp.status_code}",
                    "description": "Observed Network / Registration Information: Service unavailable",
                }

    except (httpx.TimeoutException, TimeoutError):
        logger.warning(f"RDAP lookup timed out for {clean_target} after {timeout}s")
        res = {
            "queried_value": clean_target,
            "type": actual_type,
            "status": "UNAVAILABLE",
            "error": f"RDAP lookup timeout ({timeout}s)",
            "description": "Observed Network / Registration Information: Request timeout",
        }
    except Exception as e:
        logger.warning(f"RDAP lookup error for {clean_target}: {e}")
        res = {
            "queried_value": clean_target,
            "type": actual_type,
            "status": "UNAVAILABLE",
            "error": str(e),
            "description": "Observed Network / Registration Information: Lookup failed",
        }

    if cache is not None:
        cache[clean_target] = res

    return res
