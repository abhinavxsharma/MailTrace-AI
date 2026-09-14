"""
Forensics package for MAILTRACE AI.
"""

from app.forensics.parser import parse_email_bytes
from app.forensics.headers import (
    analyze_identity_consistency,
    extract_core_headers,
    extract_address_and_domain,
)
from app.forensics.received import (
    parse_received_header,
    analyze_received_chain,
    is_valid_ipv4,
)
from app.forensics.indicators import (
    extract_indicators,
    classify_ip,
)
from app.forensics.authentication import (
    verify_email_authentication,
    parse_authentication_results_header,
    verify_spf_dns,
    verify_dkim_signature,
    evaluate_alignment,
)

__all__ = [
    "parse_email_bytes",
    "analyze_identity_consistency",
    "extract_core_headers",
    "extract_address_and_domain",
    "parse_received_header",
    "analyze_received_chain",
    "is_valid_ipv4",
    "extract_indicators",
    "classify_ip",
    "verify_email_authentication",
    "parse_authentication_results_header",
    "verify_spf_dns",
    "verify_dkim_signature",
    "evaluate_alignment",
]

