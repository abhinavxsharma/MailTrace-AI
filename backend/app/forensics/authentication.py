"""
Forensic Email Authentication and Verification Engine.
Handles RFC 7601/8601 Authentication-Results parsing, active SPF/DKIM verification,
strict/relaxed DMARC alignment, and offline DNS fallback.
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
import dns.exception
import dkim

from app.schemas.verification import (
    AuthStatus,
    AuthenticationSchema,
    DeclaredAuth,
    VerifiedAuth,
    AlignmentStatus,
)
from app.schemas.email import EmailSchema
from app.forensics.headers import extract_address_and_domain


# Strict DNS query timeout in seconds
DNS_TIMEOUT_SECONDS = 2.0


def get_dns_resolver(timeout: float = DNS_TIMEOUT_SECONDS) -> dns.resolver.Resolver:
    """Create a configured DNS resolver with strict timeouts to prevent hanging."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def normalize_auth_status(raw_status: Optional[str]) -> AuthStatus:
    """Map string representation to standard AuthStatus enum."""
    if not raw_status:
        return AuthStatus.UNKNOWN
    clean = raw_status.strip().lower()
    mapping = {
        "pass": AuthStatus.PASS,
        "fail": AuthStatus.FAIL,
        "softfail": AuthStatus.NEUTRAL,
        "neutral": AuthStatus.NEUTRAL,
        "none": AuthStatus.NONE,
        "temperror": AuthStatus.UNAVAILABLE,
        "permerror": AuthStatus.FAIL,
        "unavailable": AuthStatus.UNAVAILABLE,
        "unknown": AuthStatus.UNKNOWN,
    }
    return mapping.get(clean, AuthStatus.UNKNOWN)


# =====================================================================
# 1. Authentication-Results Header Parser
# =====================================================================

def parse_authentication_results_header(auth_results_header: Optional[str]) -> Dict[str, Any]:
    """
    Parse RFC 7601 / RFC 8601 Authentication-Results header.
    Extracts declared status and parameters for SPF, DKIM, and DMARC.
    """
    results: Dict[str, Any] = {
        "spf": {"status": AuthStatus.UNKNOWN, "domain": None, "details": None},
        "dkim": {"status": AuthStatus.UNKNOWN, "domain": None, "selector": None, "details": None},
        "dmarc": {"status": AuthStatus.UNKNOWN, "from_domain": None, "details": None},
    }

    if not auth_results_header:
        return results

    header_clean = " ".join(str(auth_results_header).split())

    # 1. SPF Parsing
    spf_match = re.search(r'\bspf=([a-zA-Z]+)', header_clean, re.IGNORECASE)
    if spf_match:
        status_str = spf_match.group(1).lower()
        results["spf"]["status"] = normalize_auth_status(status_str)
        # Extract smtp.mailfrom or smtp.helo
        mailfrom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', header_clean, re.IGNORECASE)
        helo_match = re.search(r'smtp\.helo=([^\s;]+)', header_clean, re.IGNORECASE)
        results["spf"]["domain"] = mailfrom_match.group(1) if mailfrom_match else (helo_match.group(1) if helo_match else None)
        results["spf"]["details"] = f"Declared SPF result in Authentication-Results: {status_str}"

    # 2. DKIM Parsing
    dkim_match = re.search(r'\bdkim=([a-zA-Z]+)', header_clean, re.IGNORECASE)
    if dkim_match:
        status_str = dkim_match.group(1).lower()
        results["dkim"]["status"] = normalize_auth_status(status_str)
        # Extract header.d (signing domain) and header.s (selector)
        d_match = re.search(r'header\.d=([^\s;]+)', header_clean, re.IGNORECASE)
        s_match = re.search(r'header\.s=([^\s;]+)', header_clean, re.IGNORECASE)
        results["dkim"]["domain"] = d_match.group(1) if d_match else None
        results["dkim"]["selector"] = s_match.group(1) if s_match else None
        results["dkim"]["details"] = f"Declared DKIM result in Authentication-Results: {status_str}"

    # 3. DMARC Parsing
    dmarc_match = re.search(r'\bdmarc=([a-zA-Z]+)', header_clean, re.IGNORECASE)
    if dmarc_match:
        status_str = dmarc_match.group(1).lower()
        results["dmarc"]["status"] = normalize_auth_status(status_str)
        # Extract header.from
        from_match = re.search(r'header\.from=([^\s;]+)', header_clean, re.IGNORECASE)
        results["dmarc"]["from_domain"] = from_match.group(1) if from_match else None
        results["dmarc"]["details"] = f"Declared DMARC result in Authentication-Results: {status_str}"

    return results


# =====================================================================
# 2. Active SPF Verification Engine
# =====================================================================

def verify_spf_dns(
    source_ip: Optional[str],
    sender_domain: Optional[str],
    timeout: float = DNS_TIMEOUT_SECONDS,
) -> Tuple[AuthStatus, str]:
    """
    Perform DNS TXT lookup and evaluate SPF authorization for the sending IP.
    """
    if not sender_domain or not source_ip:
        return AuthStatus.UNKNOWN, "Missing sender domain or source IP for SPF evaluation."

    try:
        ip_obj = ipaddress.ip_address(source_ip)
    except ValueError:
        return AuthStatus.UNKNOWN, f"Invalid source IP address format: '{source_ip}'"

    resolver = get_dns_resolver(timeout)
    try:
        answers = resolver.resolve(sender_domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return AuthStatus.NONE, f"No SPF record found for domain '{sender_domain}'."
    except dns.exception.Timeout:
        return AuthStatus.UNAVAILABLE, f"DNS timeout while querying SPF for domain '{sender_domain}'."
    except Exception as e:
        return AuthStatus.UNAVAILABLE, f"DNS query failed for domain '{sender_domain}': {str(e)}"

    spf_record = None
    for rdata in answers:
        txt_str = "".join([part.decode("utf-8", errors="replace") for part in rdata.strings])
        if txt_str.startswith("v=spf1"):
            spf_record = txt_str
            break

    if not spf_record:
        return AuthStatus.NONE, f"Domain '{sender_domain}' has TXT records but no v=spf1 policy."

    # Parse basic SPF mechanisms
    terms = spf_record.split()
    matched = False
    result_status = AuthStatus.NEUTRAL
    match_reason = "Evaluated default SPF policy"

    for term in terms[1:]:
        qualifier = "+"
        mech = term
        if term.startswith(("+", "-", "~", "?")):
            qualifier = term[0]
            mech = term[1:]

        if mech.startswith("ip4:"):
            cidr = mech[4:]
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in network:
                    matched = True
                    match_reason = f"Source IP {source_ip} matches mechanism '{term}'"
                    if qualifier == "+":
                        result_status = AuthStatus.PASS
                    elif qualifier == "-":
                        result_status = AuthStatus.FAIL
                    elif qualifier in ("~", "?"):
                        result_status = AuthStatus.NEUTRAL
                    break
            except Exception:
                continue
        elif mech.startswith("ip6:"):
            continue
        elif mech == "all":
            if not matched:
                match_reason = f"Matched fallback mechanism '{term}'"
                if qualifier == "+":
                    result_status = AuthStatus.PASS
                elif qualifier == "-":
                    result_status = AuthStatus.FAIL
                elif qualifier in ("~", "?"):
                    result_status = AuthStatus.NEUTRAL
                break

    return result_status, f"{match_reason} in policy: {spf_record}"


# =====================================================================
# 3. Active DKIM Verification Engine
# =====================================================================

def verify_dkim_signature(
    raw_bytes: bytes,
    timeout: float = DNS_TIMEOUT_SECONDS,
) -> Tuple[AuthStatus, Optional[str], Optional[str], str]:
    """
    Verify DKIM signature using dkimpy against raw email bytes.
    Preserves exact byte representation.
    """
    # Check if DKIM-Signature header exists in the bytes
    if b"\ndkim-signature:" not in raw_bytes.lower() and not raw_bytes.lower().startswith(b"dkim-signature:"):
        return AuthStatus.NONE, None, None, "No DKIM-Signature header present in raw email."

    # Parse signature headers to identify signing domain and selector
    signing_domain = None
    selector = None
    try:
        d_inst = dkim.DKIM(raw_bytes)
        # Parse tags from header
        for h in d_inst.headers:
            if h[0].lower() == b"dkim-signature":
                val = h[1].decode("utf-8", errors="replace")
                d_m = re.search(r'\bd=([^\s;]+)', val)
                s_m = re.search(r'\bs=([^\s;]+)', val)
                if d_m:
                    signing_domain = d_m.group(1).strip()
                if s_m:
                    selector = s_m.group(1).strip()
                break
    except Exception:
        pass

    # Execute cryptographic verification with timeout protection
    try:
        is_valid = dkim.verify(raw_bytes, timeout=timeout)
        if is_valid:
            return AuthStatus.PASS, signing_domain, selector, f"DKIM signature successfully verified for domain '{signing_domain}'."
        else:
            return AuthStatus.FAIL, signing_domain, selector, f"DKIM signature verification failed for domain '{signing_domain}'."
    except (dkim.DKIMException, dns.exception.DNSException) as e:
        return AuthStatus.UNAVAILABLE, signing_domain, selector, f"DKIM verification unavailable (key lookup failed: {str(e)})."
    except Exception as e:
        return AuthStatus.UNAVAILABLE, signing_domain, selector, f"DKIM verification encountered an error: {str(e)}."


# =====================================================================
# 4. DMARC Policy and Alignment Evaluation
# =====================================================================

def get_base_domain(domain: Optional[str]) -> Optional[str]:
    """
    Extract base organizational domain for relaxed alignment.
    e.g. mail.acme.edu -> acme.edu, notify-acme.co -> notify-acme.co
    """
    if not domain:
        return None
    parts = domain.strip().lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.strip().lower()


def evaluate_alignment(
    from_domain: Optional[str],
    spf_domain: Optional[str],
    dkim_domain: Optional[str],
    spf_status: AuthStatus,
    dkim_status: AuthStatus,
    strict_spf: bool = False,
    strict_dkim: bool = False,
) -> Tuple[AlignmentStatus, AuthStatus, str]:
    """
    Evaluate DMARC alignment between From domain, SPF Return-Path domain, and DKIM signing domain.
    """
    if not from_domain:
        return AlignmentStatus(spf=False, dkim=False, overall=False), AuthStatus.UNKNOWN, "Missing From domain for DMARC alignment."

    from_norm = from_domain.strip().lower()
    from_base = get_base_domain(from_norm)

    # 1. SPF Alignment
    spf_aligned = False
    if spf_domain and spf_status == AuthStatus.PASS:
        spf_norm = spf_domain.strip().lower()
        if strict_spf:
            spf_aligned = (spf_norm == from_norm)
        else:
            spf_aligned = (get_base_domain(spf_norm) == from_base)

    # 2. DKIM Alignment
    dkim_aligned = False
    if dkim_domain and dkim_status == AuthStatus.PASS:
        dkim_norm = dkim_domain.strip().lower()
        if strict_dkim:
            dkim_aligned = (dkim_norm == from_norm)
        else:
            dkim_aligned = (get_base_domain(dkim_norm) == from_base)

    # DMARC passes if at least one authenticated mechanism is aligned with visible From
    overall_aligned = spf_aligned or dkim_aligned
    dmarc_status = AuthStatus.PASS if overall_aligned else AuthStatus.FAIL

    reasons = []
    if spf_aligned:
        reasons.append("SPF authenticated and aligned")
    elif spf_domain and spf_status == AuthStatus.PASS:
        reasons.append(f"SPF passed for '{spf_domain}' but unaligned with visible From '{from_domain}'")
    else:
        reasons.append("SPF unaligned/failed")

    if dkim_aligned:
        reasons.append("DKIM signed and aligned")
    elif dkim_domain and dkim_status == AuthStatus.PASS:
        reasons.append(f"DKIM signed for '{dkim_domain}' but unaligned with visible From '{from_domain}'")
    else:
        reasons.append("DKIM unaligned/failed")

    details = " | ".join(reasons)
    alignment_obj = AlignmentStatus(spf=spf_aligned, dkim=dkim_aligned, overall=overall_aligned)
    return alignment_obj, dmarc_status, details


# =====================================================================
# 5. Master Verification Coordinator
# =====================================================================

def verify_email_authentication(
    raw_bytes: bytes,
    email_schema: EmailSchema,
    raw_headers: Dict[str, Any],
    source_ip: Optional[str] = None,
    timeout: float = DNS_TIMEOUT_SECONDS,
) -> AuthenticationSchema:
    """
    Coordinate complete email authentication evaluation:
    1. Parse declared Authentication-Results header
    2. Perform active SPF and DKIM verification (with safe DNS timeout/offline handling)
    3. Evaluate SPF and DKIM alignment against visible From
    4. Compute unified AuthenticationSchema
    """
    # 1. Parse declared Authentication-Results
    auth_results_header = raw_headers.get("Authentication-Results") or raw_headers.get("authentication-results")
    if isinstance(auth_results_header, list):
        auth_results_header = auth_results_header[0] if auth_results_header else None

    declared = parse_authentication_results_header(auth_results_header)

    declared_obj = DeclaredAuth(
        spf=declared["spf"]["status"],
        dkim=declared["dkim"]["status"],
        dmarc=declared["dmarc"]["status"],
    )

    # 2. Domains
    _, from_domain = extract_address_and_domain(email_schema.from_address)
    _, return_path_domain = extract_address_and_domain(email_schema.return_path)
    spf_eval_domain = return_path_domain or declared["spf"].get("domain") or from_domain

    # 3. Active SPF verification
    verified_spf_status, spf_details = verify_spf_dns(
        source_ip=source_ip,
        sender_domain=spf_eval_domain,
        timeout=timeout,
    )

    # 4. Active DKIM verification
    verified_dkim_status, dkim_domain, dkim_selector, dkim_details = verify_dkim_signature(
        raw_bytes=raw_bytes,
        timeout=timeout,
    )
    if not dkim_domain:
        dkim_domain = declared["dkim"].get("domain")

    # 5. Evaluate Alignment & DMARC
    # For alignment, we take the best available status: if active verified was PASS, use it;
    # otherwise if declared was PASS and verified was UNAVAILABLE (offline mode), we can evaluate alignment against declared.
    effective_spf_status = verified_spf_status if verified_spf_status != AuthStatus.UNAVAILABLE else declared_obj.spf
    effective_dkim_status = verified_dkim_status if verified_dkim_status != AuthStatus.UNAVAILABLE else declared_obj.dkim

    alignment_obj, dmarc_overall_status, alignment_reasons = evaluate_alignment(
        from_domain=from_domain,
        spf_domain=spf_eval_domain,
        dkim_domain=dkim_domain,
        spf_status=effective_spf_status,
        dkim_status=effective_dkim_status,
    )

    verified_obj = VerifiedAuth(
        spf=verified_spf_status,
        dkim=verified_dkim_status,
        dmarc=dmarc_overall_status if (verified_spf_status != AuthStatus.UNAVAILABLE or verified_dkim_status != AuthStatus.UNAVAILABLE) else AuthStatus.UNAVAILABLE,
    )

    # Overall headline status for schema compatibility:
    # If declared exists and active is unavailable (e.g. offline/mock environment), surface declared
    # while preserving verified in its own section.
    headline_spf = declared_obj.spf if declared_obj.spf != AuthStatus.UNKNOWN else verified_spf_status
    headline_dkim = declared_obj.dkim if declared_obj.dkim != AuthStatus.UNKNOWN else verified_dkim_status
    headline_dmarc = declared_obj.dmarc if declared_obj.dmarc != AuthStatus.UNKNOWN else dmarc_overall_status
    headline_alignment = AuthStatus.PASS if alignment_obj.overall else AuthStatus.FAIL

    return AuthenticationSchema(
        spf=headline_spf,
        dkim=headline_dkim,
        dmarc=headline_dmarc,
        alignment=headline_alignment,
        spf_details=spf_details,
        dkim_details=dkim_details,
        dmarc_details=alignment_reasons,
        declared=declared_obj,
        verified=verified_obj,
        alignment_details=alignment_obj,
        raw_results={
            "declared": declared,
            "active_spf": {"status": verified_spf_status.value, "details": spf_details},
            "active_dkim": {"status": verified_dkim_status.value, "domain": dkim_domain, "selector": dkim_selector, "details": dkim_details},
            "alignment": alignment_obj.model_dump(),
        },
    )
