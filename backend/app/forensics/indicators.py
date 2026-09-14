"""
Indicator of compromise (IOC) extraction module.
Extracts URLs, domains, and IPv4 addresses from email artifacts without external network calls.
"""

import re
import ipaddress
from urllib.parse import urlsplit
from typing import Any, Dict, List, Set, Tuple

from app.schemas.indicator import IndicatorSchema

URL_REGEX = re.compile(r'https?://[^\s<>"\'`\)]+', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})')


RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]


def classify_ip(ip_str: str) -> str:
    """
    Classify an IPv4 address string into public, private, loopback, or reserved.

    Args:
        ip_str: IPv4 string.

    Returns:
        Classification string ('public', 'private', 'loopback', 'reserved', 'invalid').
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if ip.is_loopback:
            return "loopback"
        if any(ip in net for net in RFC_1918_NETWORKS):
            return "private"
        if ip.is_multicast or ip.is_reserved:
            return "reserved"
        return "public"
    except (ValueError, ipaddress.AddressValueError):
        return "invalid"



def clean_domain(domain_str: str) -> str:
    """Clean domain string from brackets, trailing punctuation, and ports."""
    cleaned = domain_str.strip("[](){}<>\"'.,:; \t\n\r").lower()
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    return cleaned


def extract_indicators(
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    raw_headers: Dict[str, Any] = None,
) -> List[IndicatorSchema]:
    """
    Extract all unique indicators (URLs, domains, IPs) from email components.
    Safely inspects text without executing any network or DNS lookups.

    Args:
        subject: Email subject line.
        body_text: Decoded plain text body.
        body_html: Decoded HTML body.
        raw_headers: Dict of raw header strings.

    Returns:
        Deduplicated list of IndicatorSchema items.
    """
    seen: Set[Tuple[str, str, str]] = set()
    indicators: List[IndicatorSchema] = []

    def add_indicator(indicator_type: str, value: str, source: str):
        key = (indicator_type, value, source)
        if key not in seen and value:
            seen.add(key)
            indicators.append(
                IndicatorSchema(
                    type=indicator_type,
                    value=value,
                    source=source,
                    risk=None,
                )
            )

    # 1. Subject extraction
    if subject:
        # IPs in subject
        for ip in IPV4_REGEX.findall(subject):
            if classify_ip(ip) != "invalid":
                add_indicator("ip", ip, "subject")
        # Domains from emails in subject
        for dom in EMAIL_REGEX.findall(subject):
            add_indicator("domain", clean_domain(dom), "subject")

    # 2. Body extraction (text and HTML combined)
    body_combined = f"{body_text or ''}\n{body_html or ''}"
    if body_combined.strip():
        # URLs
        for url in URL_REGEX.findall(body_combined):
            url_clean = url.rstrip(".,;!?'\">")
            add_indicator("url", url_clean, "body")
            try:
                parts = urlsplit(url_clean)
                if parts.hostname:
                    hostname = clean_domain(parts.hostname)
                    if classify_ip(hostname) == "invalid":
                        add_indicator("domain", hostname, "body")
                    else:
                        add_indicator("ip", hostname, "body")
            except Exception:
                pass

        # IPs in body
        for ip in IPV4_REGEX.findall(body_combined):
            if classify_ip(ip) != "invalid":
                add_indicator("ip", ip, "body")

        # Domains in email addresses in body
        for dom in EMAIL_REGEX.findall(body_combined):
            add_indicator("domain", clean_domain(dom), "body")

    # 3. Headers extraction
    if raw_headers:
        for header_name, header_val in raw_headers.items():
            val_str = " ".join(header_val) if isinstance(header_val, list) else str(header_val)

            # Domains from email addresses
            for dom in EMAIL_REGEX.findall(val_str):
                add_indicator("domain", clean_domain(dom), f"header:{header_name.lower()}")

            # IPs in headers
            for ip in IPV4_REGEX.findall(val_str):
                if classify_ip(ip) != "invalid":
                    add_indicator("ip", ip, f"header:{header_name.lower()}")

    return indicators
