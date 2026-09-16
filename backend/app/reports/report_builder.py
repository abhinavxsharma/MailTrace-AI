"""
MAILTRACE AI - Forensic Report Data Model & Builder.
Assembles comprehensive, tamper-proof forensic investigation reports from
preserved case evidence, authentication results, AI threat inference,
infrastructure intelligence, relationship graph, and campaign correlation.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.case import Case

logger = logging.getLogger(__name__)


def generate_forensic_conclusion(report_data: Dict[str, Any]) -> str:
    """
    Generate an analyst-style forensic conclusion based strictly on observed case evidence.
    Enforces forensic safety language and avoids speculative attribution.
    """
    ai = report_data.get("ai", {})
    risk = report_data.get("risk", {})
    auth = report_data.get("authentication", {})
    features = report_data.get("features", {})
    infra = report_data.get("infrastructure", {})
    corr = report_data.get("correlation", {})

    ai_label = ai.get("classification", "BENIGN")
    ai_conf = ai.get("confidence", 0.0)
    risk_score = risk.get("score", 0)
    risk_level = risk.get("level", "LOW")

    statements: List[str] = []

    if ai_label == "MALICIOUS":
        statements.append(
            f"MAILTRACE AI sequence classification models identified MALICIOUS threat patterns "
            f"with {ai_conf:.1%} confidence."
        )
    else:
        statements.append(
            f"MAILTRACE AI sequence classification models evaluated content as BENIGN "
            f"with {ai_conf:.1%} confidence."
        )

    # Authentication & Alignment
    align = auth.get("overall_alignment", "UNKNOWN")
    if align == "FAIL":
        statements.append(
            "Cryptographic and policy verification demonstrated a critical DMARC alignment failure, "
            "indicating the message envelope does not align with the visible From domain."
        )
    elif align == "PASS":
        statements.append("Authentication checks confirmed valid DMARC alignment with the sender domain.")

    # Identity mismatches
    mismatches: List[str] = []
    if features.get("reply_to_mismatch"):
        mismatches.append("Reply-To destination inconsistency")
    if features.get("return_path_mismatch"):
        mismatches.append("Return-Path envelope inconsistency")
    if mismatches:
        statements.append(f"Identity consistency checks revealed: {', '.join(mismatches)}.")

    # Behavioral indicators
    cues: List[str] = []
    if features.get("urgency"):
        cues.append("artificial urgency")
    if features.get("financial"):
        cues.append("financial / remittance coercion")
    if features.get("credentials"):
        cues.append("credential verification harvesting")
    if cues:
        statements.append(f"Linguistic and structural analysis flagged: {', '.join(cues)}.")

    # Infrastructure
    src_ip = infra.get("source_ip")
    if src_ip and src_ip != "Unavailable":
        geo_country = infra.get("geoip", {}).get("country")
        org = infra.get("rdap", {}).get("organization")
        infra_desc = f"Observed source infrastructure ({src_ip})"
        if org:
            infra_desc += f" routed through {org}"
        if geo_country:
            infra_desc += f" (IP Geolocation: {geo_country})"
        statements.append(f"{infra_desc}.")

    # Campaign correlation
    related = corr.get("related_cases", [])
    if related:
        strength = corr.get("relationship_strength", "LOW")
        statements.append(
            f"Cross-case correlation detected a potential campaign relationship of {strength} strength "
            f"sharing infrastructure observables with {len(related)} related investigation(s)."
        )

    # Conclusion summary
    verdict = (
        f"Overall Forensic Assessment: The investigation yields a composite risk score of {risk_score}/100 "
        f"({risk_level} Risk). {' '.join(statements)}"
    )

    return verdict


def build_case_report(db: Session, case_identifier: str) -> Dict[str, Any]:
    """
    Assemble complete forensic report object from database records and stored analysis.
    Does not make external network requests or mutate original case evidence.
    """
    # 1. Query Case
    case = db.query(Case).filter(
        (Case.case_number == case_identifier) | (Case.id == (int(case_identifier) if case_identifier.isdigit() else -1))
    ).first()

    if not case:
        raise ValueError(f"Case '{case_identifier}' was not found in the forensic repository.")

    # 2. Parse Analysis JSON
    analysis_data: Dict[str, Any] = {}
    if case.analysis_json:
        try:
            analysis_data = json.loads(case.analysis_json)
        except Exception as e:
            logger.warning(f"Could not parse analysis_json for case {case.case_number}: {e}")
            analysis_data = {}

    now_iso = datetime.now(timezone.utc).isoformat()
    created_iso = case.created_at.isoformat() if case.created_at else now_iso
    updated_iso = case.updated_at.isoformat() if case.updated_at else now_iso

    # 3. Evidence Artifacts & Original SHA-256 Fingerprint
    evidence_list: List[Dict[str, Any]] = []
    original_sha256 = "UNKNOWN"
    primary_filename = case.original_filename or case.filename or "raw.eml"
    primary_filesize = 0

    if case.evidences:
        for ev in case.evidences:
            if ev.evidence_type == "raw_eml":
                original_sha256 = ev.sha256
                primary_filename = ev.filename
                primary_filesize = ev.size_bytes or 0

            evidence_list.append({
                "id": ev.id,
                "evidence_type": ev.evidence_type,
                "filename": ev.filename,
                "path": ev.path,
                "sha256": ev.sha256,
                "size_bytes": ev.size_bytes,
                "preservation_status": "SECURED_IMMUTABLE",
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            })

    # 4. Email Metadata
    email_data = analysis_data.get("email", {})
    email_section = {
        "subject": email_data.get("subject") or "Untitled",
        "from": email_data.get("from_address"),
        "to": email_data.get("to_address"),
        "reply_to": email_data.get("reply_to"),
        "return_path": email_data.get("return_path"),
        "date": email_data.get("date"),
        "message_id": email_data.get("message_id"),
        "body_preview": (email_data.get("body_text") or "")[:500],
    }

    # 5. Forensics & Indicators
    indicators = analysis_data.get("indicators", [])
    extracted_urls: List[str] = []
    extracted_domains: List[str] = []
    extracted_ips: List[str] = []

    for ind in indicators:
        itype = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", "")
        ival = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", "")
        if itype == "url" and ival not in extracted_urls:
            extracted_urls.append(ival)
        elif itype == "domain" and ival not in extracted_domains:
            extracted_domains.append(ival)
        elif itype == "ip" and ival not in extracted_ips:
            extracted_ips.append(ival)

    identity_info = analysis_data.get("identity", {})
    forensics_section = {
        "extracted_urls": extracted_urls,
        "extracted_domains": extracted_domains,
        "extracted_ips": extracted_ips,
        "received_hops": analysis_data.get("received_chain", []),
        "identity_consistency": {
            "from_domain": identity_info.get("from_domain"),
            "reply_to_domain": identity_info.get("reply_to_domain"),
            "return_path_domain": identity_info.get("return_path_domain"),
            "reply_to_mismatch": identity_info.get("reply_to_mismatch", False),
            "return_path_mismatch": identity_info.get("return_path_mismatch", False),
        },
    }

    # 6. Authentication Section
    auth_data = analysis_data.get("authentication", {})
    auth_section = {
        "spf": auth_data.get("spf", "UNKNOWN"),
        "dkim": auth_data.get("dkim", "UNKNOWN"),
        "dmarc": auth_data.get("dmarc", "UNKNOWN"),
        "spf_alignment": auth_data.get("spf_details", {}).get("status") if isinstance(auth_data.get("spf_details"), dict) else "UNKNOWN",
        "dkim_alignment": auth_data.get("dkim_details", {}).get("status") if isinstance(auth_data.get("dkim_details"), dict) else "UNKNOWN",
        "overall_alignment": auth_data.get("alignment", "UNKNOWN"),
        "declared": auth_data.get("declared", {}),
        "verified": auth_data.get("verified", {}),
    }

    # 7. AI Threat Detection Section
    det = analysis_data.get("detection", {})
    ai_section = {
        "model": det.get("model") or "DistilBERT (dataset3_v1.0.0)",
        "version": det.get("version") or "1.0.0",
        "classification": det.get("label") or case.classification or "BENIGN",
        "confidence": float(det.get("confidence") or case.confidence or 0.0),
        "threat_score": det.get("threat_score"),
    }

    # 8. Forensic Features Section
    feat = analysis_data.get("features", {})
    features_section = {
        "urgency": feat.get("urgency_detected", False),
        "financial": feat.get("financial_detected", False),
        "credentials": feat.get("credentials_detected", False),
        "authority": feat.get("authority_detected", False),
        "secrecy": feat.get("secrecy_detected", False),
        "action_request": feat.get("urgency_detected", False) or feat.get("financial_detected", False),
        "suspicious_links": feat.get("suspicious_links_detected", False),
        "reply_to_mismatch": feat.get("reply_to_mismatch", False),
        "return_path_mismatch": feat.get("return_path_mismatch", False),
        "url_count": feat.get("url_count", len(extracted_urls)),
        "domain_count": feat.get("domain_count", len(extracted_domains)),
        "ip_count": feat.get("ip_count", len(extracted_ips)),
    }

    # 9. Infrastructure Intelligence Section
    infra_dict = analysis_data.get("infrastructure", {})
    source_ip = infra_dict.get("source_ip") or (extracted_ips[0] if extracted_ips else "Unavailable")
    rdap_records = analysis_data.get("rdap", {})
    geoip_records = analysis_data.get("geoip", {})
    dns_records = analysis_data.get("dns", {})

    ip_rdap = rdap_records.get(source_ip, {}) if source_ip in rdap_records else {}
    ip_geo = geoip_records.get(source_ip, {}) if source_ip in geoip_records else {}

    infrastructure_section = {
        "source_ip": source_ip,
        "reverse_dns": infra_dict.get("reverse_dns") or "No PTR record",
        "asn": infra_dict.get("asn") or "Autonomous System",
        "organization": ip_rdap.get("organization") or infra_dict.get("organization") or "Unavailable",
        "network_name": ip_rdap.get("network_name") or "Unavailable",
        "country": ip_geo.get("country") or infra_dict.get("country") or "Unavailable",
        "city": ip_geo.get("city") or "Unavailable",
        "dns": dns_records,
        "rdap": ip_rdap,
        "geoip": ip_geo,
        "infrastructure_score": analysis_data.get("infrastructure_score", 0),
        "observed_infrastructure_evidence": f"Observed host {source_ip} ({ip_rdap.get('organization') or 'Network'})",
    }

    # 10. Relationship Graph Section
    graph_data = analysis_data.get("graph", {})
    graph_section = {
        "node_count": graph_data.get("node_count", 0),
        "edge_count": graph_data.get("edge_count", 0),
        "nodes": graph_data.get("nodes", []),
        "edges": graph_data.get("edges", []),
    }

    # 11. Campaign Correlation Section
    corr_data = analysis_data.get("correlation", {})
    correlation_section = {
        "related_cases": corr_data.get("related_case_ids", []),
        "shared_indicators": corr_data.get("shared_indicators", []),
        "relationship_strength": corr_data.get("relationship_strength", "NONE"),
        "campaign_score": analysis_data.get("campaign_score", corr_data.get("campaign_score", 0)),
        "correlation_reasons": corr_data.get("correlation_reasons", []),
    }

    # 12. Forensic Timeline Section
    timeline_section = analysis_data.get("timeline", [])

    # 13. Risk Scoring & Explainable Contributions
    contribs = analysis_data.get("risk_contributions", {})
    risk_section = {
        "score": case.risk_score if case.risk_score is not None else analysis_data.get("risk_score", 0),
        "level": case.classification or analysis_data.get("classification", "LOW"),
        "confidence": float(case.confidence or analysis_data.get("confidence", 0.85)),
        "contributions": {
            "ai_threat": contribs.get("ai_threat", 0),
            "identity": contribs.get("identity", 0),
            "authentication": contribs.get("authentication", 0),
            "url_domain": contribs.get("url_domain", 0),
            "infrastructure": contribs.get("infrastructure", 0),
            "campaign": contribs.get("campaign", 0),
        },
        "reasons": analysis_data.get("reasons", []),
        "explanations": analysis_data.get("explanations", []),
    }

    # 14. Audit Events
    audit_list: List[Dict[str, Any]] = []
    if case.audit_events:
        for a in case.audit_events:
            audit_list.append({
                "id": a.id,
                "event_type": a.event_type,
                "description": a.description,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })

    # Assemble Base Report Structure
    report: Dict[str, Any] = {
        "report_id": f"REP-{case.case_number}",
        "generation_timestamp": now_iso,
        "case_id": case.case_number,
        "case_status": case.status,
        "created_at": created_iso,
        "updated_at": updated_iso,
        "email": email_section,
        "evidence": {
            "original_filename": primary_filename,
            "file_size": primary_filesize,
            "sha256": original_sha256,
            "chain_of_custody": evidence_list,
        },
        "forensics": forensics_section,
        "authentication": auth_section,
        "ai": ai_section,
        "features": features_section,
        "infrastructure": infrastructure_section,
        "graph": graph_section,
        "correlation": correlation_section,
        "timeline": timeline_section,
        "risk": risk_section,
        "audit": audit_list,
        "forensic_disclaimer": (
            "FORENSIC SAFEGUARD STATEMENT: Observed source infrastructure reflects technical network routing artifacts "
            "and hosting registry allocations. IP Geolocation is approximate and does not prove human identity or exact "
            "physical location. Cross-case campaign correlation establishes potential shared infrastructure relationships "
            "and does not assert confirmation of a specific human actor."
        ),
    }

    # Generate analytical conclusion
    report["conclusion"] = generate_forensic_conclusion(report)

    return report
