"""
Header normalization and identity inconsistency analysis.
Compares From, Reply-To, and Return-Path addresses using safe forensic terminology.
"""

import re
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.verification import IdentitySchema


def extract_address_and_domain(header_value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract normalized email address and domain from an RFC 5322 header string.
    e.g. 'CFO <cfo@acme-finance.com>' -> ('cfo@acme-finance.com', 'acme-finance.com')
    """
    if not header_value:
        return None, None
    _, addr = parseaddr(str(header_value))
    if not addr or "@" not in addr:
        # Fallback regex for angle brackets or plain string
        match = re.search(r'[\w\.-]+@[\w\.-]+', str(header_value))
        addr = match.group(0) if match else None
    if not addr:
        return None, None
    addr_clean = addr.strip().lower()
    domain = addr_clean.split("@")[-1]
    return addr_clean, domain


def analyze_identity_consistency(
    from_header: Optional[str],
    reply_to_header: Optional[str],
    return_path_header: Optional[str],
) -> IdentitySchema:
    """
    Evaluate alignment between From, Reply-To, and Return-Path.
    Generates structured discrepancy findings without speculative attribution.
    """
    from_addr, from_domain = extract_address_and_domain(from_header)
    reply_addr, reply_domain = extract_address_and_domain(reply_to_header)
    return_addr, return_domain = extract_address_and_domain(return_path_header)

    mismatches: List[str] = []
    mismatch_detected = False

    # Compare From vs Reply-To
    reply_to_mismatch = False
    if reply_addr and from_addr:
        if reply_domain != from_domain:
            reply_to_mismatch = True
            mismatch_detected = True
            mismatches.append(
                f"Visible From domain ({from_domain}) differs from Reply-To destination domain ({reply_domain}). "
                f"Observed identity inconsistency in reply routing."
            )
        elif reply_addr != from_addr:
            reply_to_mismatch = True
            mismatch_detected = True
            mismatches.append(
                f"Visible From address ({from_addr}) differs from Reply-To address ({reply_addr})."
            )

    # Compare From vs Return-Path
    return_path_mismatch = False
    if return_domain and from_domain and return_domain != from_domain:
        return_path_mismatch = True
        mismatch_detected = True
        mismatches.append(
            f"Visible From domain ({from_domain}) differs from envelope Return-Path domain ({return_domain}). "
            f"Observed identity inconsistency in delivery origin."
        )

    details = " | ".join(mismatches) if mismatches else "Sender and reply routing identities are consistent."

    return IdentitySchema(
        from_address=from_header,
        reply_to=reply_to_header,
        return_path=return_path_header,
        from_domain=from_domain,
        reply_to_domain=reply_domain,
        return_path_domain=return_domain,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        mismatch_detected=mismatch_detected,
        details=details,
    )



def extract_core_headers(raw_headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract normalized forensic headers subset.
    Preserves repeated headers such as Received.
    """
    keys_of_interest = [
        "From",
        "To",
        "Cc",
        "Reply-To",
        "Return-Path",
        "Subject",
        "Date",
        "Message-ID",
        "Received",
        "Authentication-Results",
        "DKIM-Signature",
    ]
    extracted: Dict[str, Any] = {}
    for key in keys_of_interest:
        # Case-insensitive lookup
        matching_key = next((k for k in raw_headers.keys() if k.lower() == key.lower()), None)
        if matching_key:
            extracted[key] = raw_headers[matching_key]
        else:
            extracted[key] = [] if key == "Received" else None
    return extracted
