"""
Received header chronology and hop reconstruction.
Analyzes mail transfer agent (MTA) relay chain to identify observed source infrastructure.
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional

IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
FROM_REGEX = re.compile(r'from\s+([^\s\(;]+)', re.IGNORECASE)
BY_REGEX = re.compile(r'by\s+([^\s\(;]+)', re.IGNORECASE)
DATE_REGEX = re.compile(r';\s*([A-Za-z0-9, :+-]+)$')


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def parse_received_header(raw_header: str) -> Dict[str, Any]:
    """
    Parse an individual RFC 5322 Received header into structured hop metadata.

    Args:
        raw_header: Single unparsed Received header string.

    Returns:
        Dict with from_host, by_host, source_ip, timestamp, and raw_header.
    """
    cleaned = " ".join(raw_header.split())

    from_match = FROM_REGEX.search(cleaned)
    from_host = from_match.group(1).strip() if from_match else None

    by_match = BY_REGEX.search(cleaned)
    by_host = by_match.group(1).strip() if by_match else None

    # Search for IP addresses in the hop record
    ips = IPV4_REGEX.findall(cleaned)
    source_ip = None
    for ip in ips:
        if is_valid_ipv4(ip):
            source_ip = ip
            break

    # Extract date/time after semicolon if present
    date_match = DATE_REGEX.search(cleaned)
    timestamp = date_match.group(1).strip() if date_match else None

    return {
        "raw_header": raw_header,
        "from_host": from_host,
        "by_host": by_host,
        "source_ip": source_ip,
        "timestamp": timestamp,
    }


RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]


def is_private_or_internal(ip_str: str) -> bool:
    """Check if IP address belongs to RFC 1918 private space or loopback."""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_loopback:
            return True
        if any(ip in net for net in RFC_1918_NETWORKS):
            return True
        return False
    except Exception:
        return False


def analyze_received_chain(received_headers: List[str]) -> Dict[str, Any]:
    """
    Parse all Received headers preserving order, and identify observed source infrastructure.

    Args:
        received_headers: List of Received header strings in message order.

    Returns:
        Dict containing hops list, hop count, and observed_source_ip.
    """
    hops = [parse_received_header(h) for h in received_headers]

    # In RFC 5322, Received headers are prepended by each MTA.
    # The earliest hop is at the end of the list.
    observed_source_ip: Optional[str] = None
    all_ips: List[str] = []

    for hop in reversed(hops):
        ip = hop.get("source_ip")
        if ip and is_valid_ipv4(ip):
            all_ips.append(ip)
            if not is_private_or_internal(ip):
                if not observed_source_ip:
                    observed_source_ip = ip

    if not observed_source_ip and all_ips:
        observed_source_ip = all_ips[0]

    return {
        "hops": hops,
        "hop_count": len(hops),
        "observed_source_ip": observed_source_ip,
    }

