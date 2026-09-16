"""
MAILTRACE AI - Passive DNS Intelligence Service.
Performs safe, non-intrusive DNS resolution for extracted domains with strict timeouts and caching.
"""

import logging
from typing import Any, Dict, List, Optional
import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

SUPPORTED_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]
DEFAULT_DNS_TIMEOUT = 2.0


def _clean_domain(domain_input: str) -> str:
    """Clean and normalize domain input."""
    if not domain_input:
        return ""
    d = domain_input.strip().lower()
    # Remove protocol prefix if present
    if "://" in d:
        d = d.split("://", 1)[1]
    # Remove port or path
    d = d.split("/", 1)[0].split(":", 1)[0]
    # Remove trailing dot
    return d.rstrip(".")


def resolve_dns_records(
    domain: str,
    record_types: Optional[List[str]] = None,
    cache: Optional[Dict[str, Any]] = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
) -> Dict[str, Any]:
    """
    Safely resolve DNS records (A, AAAA, MX, NS, TXT) for a domain.
    Never executes or visits URLs.
    Returns structured status: AVAILABLE, UNAVAILABLE, or NOT_FOUND.
    """
    clean_dom = _clean_domain(domain)
    if not clean_dom or "." not in clean_dom:
        return {
            "domain": domain,
            "status": "NOT_FOUND",
            "records": {rt: [] for rt in SUPPORTED_RECORD_TYPES},
            "has_mx": False,
            "error": "Invalid domain name",
        }

    # Check in-memory lookup cache
    if cache is not None and clean_dom in cache:
        return cache[clean_dom]

    types_to_query = record_types or SUPPORTED_RECORD_TYPES
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    records: Dict[str, List[Any]] = {rt: [] for rt in SUPPORTED_RECORD_TYPES}
    any_success = False
    is_nxdomain = False
    timeout_occurred = False
    error_msg = None

    for rtype in types_to_query:
        if rtype not in SUPPORTED_RECORD_TYPES:
            continue
        try:
            answers = resolver.resolve(clean_dom, rtype)
            for rdata in answers:
                if rtype == "A" or rtype == "AAAA":
                    records[rtype].append(rdata.address)
                elif rtype == "MX":
                    records[rtype].append({
                        "exchange": str(rdata.exchange).rstrip("."),
                        "preference": rdata.preference,
                    })
                elif rtype == "NS":
                    records[rtype].append(str(rdata.target).rstrip("."))
                elif rtype == "TXT":
                    records[rtype].append(rdata.to_text().strip('"'))
            if records[rtype]:
                any_success = True

        except dns.resolver.NXDOMAIN:
            is_nxdomain = True
            break
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # Record type does not exist for this domain
            continue
        except (dns.exception.Timeout, TimeoutError):
            timeout_occurred = True
            error_msg = f"DNS query timeout ({timeout}s) for {clean_dom} {rtype}"
            logger.warning(error_msg)
        except Exception as e:
            error_msg = f"DNS resolution error for {clean_dom} {rtype}: {e}"
            logger.debug(error_msg)

    # Determine structured status
    if is_nxdomain:
        status = "NOT_FOUND"
    elif any_success:
        status = "AVAILABLE"
    elif timeout_occurred:
        status = "UNAVAILABLE"
    else:
        status = "NOT_FOUND"

    result = {
        "domain": clean_dom,
        "status": status,
        "records": records,
        "has_mx": bool(records.get("MX")),
        "error": error_msg,
    }

    if cache is not None:
        cache[clean_dom] = result

    return result
