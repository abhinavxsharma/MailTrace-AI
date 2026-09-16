"""
MAILTRACE AI - Cross-Case Campaign Correlation Engine.
Identifies related forensic investigations and campaign clusters sharing meaningful
threat indicators (Reply-To, source IP, URL domains, return paths).
Note: Forensics safety rule - correlation establishes potential campaign relationships,
never definitive human attacker identity.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.models.case import Case
from app.graph.builder import _normalize_domain, _normalize_email

logger = logging.getLogger(__name__)

# Common public mail providers / TLDs to exclude from raw domain-only collisions
GENERIC_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "aol.com"}
MAX_CAMPAIGN_SCORE = 10


def _extract_case_indicators(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract normalized correlation indicators from a case's analysis data."""
    from app.forensics.indicators import classify_ip

    email = analysis_data.get("email", {})
    from_addr = _normalize_email(email.get("from_address"))
    reply_to = _normalize_email(email.get("reply_to"))
    return_path = _normalize_email(email.get("return_path"))
    recipient = _normalize_email(email.get("to_address") or email.get("to"))
    recipient_domain = _normalize_domain(recipient.split("@", 1)[1]) if recipient and "@" in recipient else None

    return_path_dom = None
    if return_path and "@" in return_path:
        return_path_dom = _normalize_domain(return_path.split("@", 1)[1])

    source_ip = analysis_data.get("infrastructure", {}).get("source_ip")
    if source_ip:
        source_ip = source_ip.strip()
        # Only correlate on valid public source IPs, not private/internal addresses
        if classify_ip(source_ip) not in ("public",):
            source_ip = None

    # URL domains
    url_domains: Set[str] = set()
    for ind in analysis_data.get("indicators", []):
        t = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", None)
        v = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", None)
        src = ind.get("source") if isinstance(ind, dict) else getattr(ind, "source", None)
        if not v:
            continue
        if t == "url":
            if "://" in v:
                host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                cd = _normalize_domain(host)
                if cd and cd not in GENERIC_DOMAINS and cd != recipient_domain:
                    url_domains.add(cd)
        elif t == "domain":
            # Exclude internal recipient or transit hop header domains
            if src and (src.startswith("header:to") or src.startswith("header:received")):
                continue
            cd = _normalize_domain(v)
            if cd and cd not in GENERIC_DOMAINS and cd != recipient_domain:
                url_domains.add(cd)

    return {
        "sender": from_addr,
        "reply_to": reply_to,
        "return_path_domain": return_path_dom,
        "source_ip": source_ip,
        "url_domains": sorted(list(url_domains)),
    }


def correlate_case(
    db: Session,
    target_case: Case,
) -> Dict[str, Any]:
    """
    Correlate target case against all existing database cases.
    Identifies shared indicators and computes deterministic relationship strength.
    """
    target_analysis: Dict[str, Any] = {}
    if target_case.analysis_json:
        try:
            target_analysis = json.loads(target_case.analysis_json)
        except Exception:
            target_analysis = {}

    target_indicators = _extract_case_indicators(target_analysis)

    related_case_ids: List[str] = []
    shared_indicators: List[Dict[str, Any]] = []
    correlation_reasons: List[str] = []
    max_strength_points = 0

    # Query all other cases
    candidates = db.query(Case).filter(Case.id != target_case.id).all()

    for cand in candidates:
        if not cand.analysis_json:
            continue
        try:
            cand_analysis = json.loads(cand.analysis_json)
        except Exception:
            continue

        cand_indicators = _extract_case_indicators(cand_analysis)
        strength = 0
        case_reasons: List[str] = []

        # 1. Match Reply-To address (strong indicator, weight 5)
        if (
            target_indicators["reply_to"]
            and cand_indicators["reply_to"]
            and target_indicators["reply_to"] == cand_indicators["reply_to"]
        ):
            val = target_indicators["reply_to"]
            strength += 5
            shared_indicators.append({
                "type": "reply_to",
                "value": val,
                "related_case": cand.case_number,
            })
            case_reasons.append(f"Shared Reply-To address '{val}'")

        # 2. Match observed public source IP (strong indicator, weight 4)
        if (
            target_indicators["source_ip"]
            and cand_indicators["source_ip"]
            and target_indicators["source_ip"] == cand_indicators["source_ip"]
        ):
            val = target_indicators["source_ip"]
            strength += 4
            shared_indicators.append({
                "type": "source_ip",
                "value": val,
                "related_case": cand.case_number,
            })
            case_reasons.append(f"Shared Observed Source IP '{val}'")

        # 3. Match URL domains (weight 4)
        common_domains = set(target_indicators["url_domains"]).intersection(set(cand_indicators["url_domains"]))
        for cdom in common_domains:
            strength += 4
            shared_indicators.append({
                "type": "domain",
                "value": cdom,
                "related_case": cand.case_number,
            })
            case_reasons.append(f"Shared destination domain '{cdom}'")

        # 4. Match Return-Path domain (weight 3)
        if (
            target_indicators["return_path_domain"]
            and cand_indicators["return_path_domain"]
            and target_indicators["return_path_domain"] == cand_indicators["return_path_domain"]
            and target_indicators["return_path_domain"] not in GENERIC_DOMAINS
        ):
            val = target_indicators["return_path_domain"]
            strength += 3
            shared_indicators.append({
                "type": "return_path_domain",
                "value": val,
                "related_case": cand.case_number,
            })
            case_reasons.append(f"Shared Return-Path domain '{val}'")

        # 5. Match sender address (weight 2)
        if (
            target_indicators["sender"]
            and cand_indicators["sender"]
            and target_indicators["sender"] == cand_indicators["sender"]
        ):
            val = target_indicators["sender"]
            strength += 2
            shared_indicators.append({
                "type": "sender",
                "value": val,
                "related_case": cand.case_number,
            })
            case_reasons.append(f"Shared From address '{val}'")

        if strength >= 3:
            related_case_ids.append(cand.case_number)
            for r in case_reasons:
                reason_stmt = f"Potential Campaign Relationship: {r} observed with case {cand.case_number}."
                if reason_stmt not in correlation_reasons:
                    correlation_reasons.append(reason_stmt)
            if strength > max_strength_points:
                max_strength_points = strength

    # Determine relationship strength level
    if max_strength_points >= 8:
        rel_strength = "HIGH"
    elif max_strength_points >= 5:
        rel_strength = "MEDIUM"
    elif max_strength_points >= 3:
        rel_strength = "LOW"
    else:
        rel_strength = "NONE"

    # Evaluate campaign risk contribution
    campaign_score = evaluate_campaign_score({
        "related_case_ids": related_case_ids,
        "shared_indicators": shared_indicators,
        "strength_points": max_strength_points,
    })

    return {
        "related_case_ids": related_case_ids,
        "shared_indicators": shared_indicators,
        "relationship_strength": rel_strength,
        "correlation_reasons": correlation_reasons,
        "campaign_score": campaign_score,
    }


def evaluate_campaign_score(correlation_result: Dict[str, Any]) -> int:
    """
    Calculate deterministic 0-10 campaign risk points based strictly on verified shared evidence.
    No correlation = 0 points.
    """
    shared = correlation_result.get("shared_indicators", [])
    if not shared:
        return 0

    points = 0
    types_found = {item.get("type") for item in shared}

    if "reply_to" in types_found:
        points += 5
    if "source_ip" in types_found:
        points += 4
    if "domain" in types_found:
        points += 4
    if "return_path_domain" in types_found:
        points += 2

    return min(MAX_CAMPAIGN_SCORE, points)
