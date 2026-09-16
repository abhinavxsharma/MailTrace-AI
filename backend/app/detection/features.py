"""
MAILTRACE AI - Forensic Linguistic and Structural Feature Extraction.
Extracts deterministic linguistic, credential, authority, and identity signals from parsed emails.
"""

import re
from typing import Any, Dict, List, Optional, Set

from app.schemas.email import EmailSchema
from app.schemas.indicator import IndicatorSchema
from app.schemas.verification import IdentitySchema
from app.detection.classifier import strip_html_tags


# Deterministic pattern definitions
URGENCY_KEYWORDS = [
    "urgent",
    "urgently",
    "immediately",
    "today",
    "asap",
    "critical",
    "action required",
    "time-sensitive",
    "expedite",
    "deadline",
    "suspended",
    "expires",
    "within 24 hours",
    "24 hours",
    "immediate attention",
]

FINANCIAL_KEYWORDS = [
    "invoice",
    "bank account",
    "beneficiary",
    "wire transfer",
    "payment",
    "banking partner",
    "routing number",
    "remittance",
    "funds",
    "settlement",
    "vendor invoice",
    "account details",
    "bank transfer",
    "swift",
    "iban",
    "payroll",
    "direct deposit",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "login",
    "sign in",
    "sign-in",
    "verify account",
    "verify identity",
    "verify your identity",
    "credentials",
    "update payment details",
    "security code",
    "mfa",
    "reset password",
    "verify invoice",
    "portal",
    "access code",
    "confirm identity",
    "passcode",
]

AUTHORITY_KEYWORDS = [
    "cfo",
    "ceo",
    "president",
    "director",
    "executive",
    "board",
    "management",
    "chairman",
    "founder",
    "head of finance",
    "chief financial officer",
    "chief executive officer",
    "treasurer",
]

SECRECY_KEYWORDS = [
    "do not call",
    "confidential",
    "keep this private",
    "do not disclose",
    "in a meeting",
    "do not discuss",
    "strictly confidential",
    "keep between us",
    "discreet",
]

REQUEST_ACTION_KEYWORDS = [
    "please process",
    "click here",
    "verify",
    "update",
    "confirm",
    "follow link",
    "review and sign",
    "open the attachment",
    "kindly confirm",
    "action required",
]

SUSPICIOUS_LINK_KEYWORDS = [
    "verify-invoice",
    "secure-login",
    "account-update",
    "secure-",
    "-login",
    "-portal",
    "auth-",
    "confirm-identity",
    "banking-",
    "webscr",
    "signin",
    "checkpoint",
    "verify",
]

ATTACHMENT_KEYWORDS = [
    "see attached",
    "attached invoice",
    "attachment",
    "enclosed",
    "download attachment",
    "attached document",
    "receipt attached",
]

PHISHING_PHRASES = [
    "verify your account",
    "urgent action required",
    "account will be suspended",
    "update payment details",
    "change vendor bank account",
    "beneficiary account",
    "security alert",
    "suspicious activity detected",
]


def _match_keywords(text: str, keywords: List[str]) -> List[str]:
    """Find all matching keywords/phrases in text using case-insensitive search."""
    if not text:
        return []
    lower = text.lower()
    matched: Set[str] = set()
    for kw in keywords:
        # Use regex boundary matching where appropriate or substring for hyphenated/phrases
        pattern = r"\b" + re.escape(kw) + r"\b" if " " in kw or "-" in kw else r"\b" + re.escape(kw) + r"\b"
        if re.search(pattern, lower):
            matched.add(kw)
    return sorted(list(matched))


def extract_forensic_features(
    email: EmailSchema,
    indicators: Optional[List[IndicatorSchema]] = None,
    identity: Optional[IdentitySchema] = None,
) -> Dict[str, Any]:
    """
    Extract linguistic, structural, and identity features from an email.
    Returns a dictionary of boolean flags, counts, matched cues, and human-readable explanations.
    """
    subject = (email.subject or "").strip()
    body = (email.body_text or "").strip()
    if not body and email.body_html:
        body = strip_html_tags(email.body_html)

    combined_text = f"{subject}\n\n{body}".strip()

    # Extract linguistic signals
    urgency_matches = _match_keywords(combined_text, URGENCY_KEYWORDS)
    financial_matches = _match_keywords(combined_text, FINANCIAL_KEYWORDS)
    credential_matches = _match_keywords(combined_text, CREDENTIAL_KEYWORDS)
    authority_matches = _match_keywords(combined_text, AUTHORITY_KEYWORDS)
    secrecy_matches = _match_keywords(combined_text, SECRECY_KEYWORDS)
    request_action_matches = _match_keywords(combined_text, REQUEST_ACTION_KEYWORDS)
    attachment_matches = _match_keywords(combined_text, ATTACHMENT_KEYWORDS)
    phishing_phrase_matches = _match_keywords(combined_text, PHISHING_PHRASES)

    # URL / link analysis from indicators
    urls: List[str] = []
    domains: List[str] = []
    if indicators:
        for ind in indicators:
            if ind.type == "url":
                urls.append(ind.value)
            elif ind.type == "domain":
                domains.append(ind.value)

    # Also search links in body for suspicious link keywords
    suspicious_link_matches: Set[str] = set()
    for u in urls:
        u_lower = u.lower()
        for kw in SUSPICIOUS_LINK_KEYWORDS:
            if kw in u_lower:
                suspicious_link_matches.add(kw)

    # Identity signals
    reply_to_mismatch = False
    return_path_mismatch = False
    if identity:
        reply_to_mismatch = identity.reply_to_mismatch
        return_path_mismatch = identity.return_path_mismatch

    # Compile human-readable explanations
    explanations: List[str] = []
    if urgency_matches:
        explanations.append(f"Email contains urgent/time-sensitive language: {', '.join(urgency_matches[:3])}")
    if financial_matches:
        explanations.append(f"Email contains financial/wire-transfer language: {', '.join(financial_matches[:3])}")
    if credential_matches:
        explanations.append(f"Email contains credential/portal verification prompts: {', '.join(credential_matches[:3])}")
    if authority_matches:
        explanations.append(f"Executive/authority impersonation cues observed: {', '.join(authority_matches[:3])}")
    if secrecy_matches:
        explanations.append(f"Secrecy or non-verification coercion observed: {', '.join(secrecy_matches[:3])}")
    if suspicious_link_matches:
        explanations.append(f"Suspicious URL patterns detected in extracted links: {', '.join(sorted(list(suspicious_link_matches))[:3])}")
    if reply_to_mismatch:
        explanations.append("Visible From domain differs from Reply-To domain")
    if return_path_mismatch:
        explanations.append("Visible From domain differs from Return-Path domain")

    return {
        "urgency_detected": bool(urgency_matches),
        "financial_detected": bool(financial_matches),
        "credentials_detected": bool(credential_matches),
        "authority_detected": bool(authority_matches),
        "secrecy_detected": bool(secrecy_matches),
        "request_action_detected": bool(request_action_matches),
        "suspicious_links_detected": bool(suspicious_link_matches),
        "attachment_cues_detected": bool(attachment_matches),
        "phishing_phrases_detected": bool(phishing_phrase_matches),
        "url_count": len(urls),
        "domain_count": len(domains),
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "matched_cues": {
            "urgency": urgency_matches,
            "financial": financial_matches,
            "credentials": credential_matches,
            "authority": authority_matches,
            "secrecy": secrecy_matches,
            "request_action": request_action_matches,
            "suspicious_links": sorted(list(suspicious_link_matches)),
            "attachment_cues": attachment_matches,
            "phishing_phrases": phishing_phrase_matches,
        },
        "explanations": explanations,
    }
