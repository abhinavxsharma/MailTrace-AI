"""
Unit tests for Phase 9 Forensic Report Builder.
Validates report assembly, immutability of evidence fingerprints,
inclusion of AI/auth/infra/graph/campaign/risk sections, and forensic wording safeguards.
"""

import json
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.audit_event import AuditEvent
from app.reports.report_builder import build_case_report, generate_forensic_conclusion


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def populated_case(memory_db):
    """Create a fully analyzed synthetic case in DB with all forensic analysis data."""
    case = Case(
        case_number="MT-2026-000042",
        filename="invoice_urgent.eml",
        original_filename="invoice_urgent.eml",
        status="ANALYZED",
        risk_score=85,
        classification="HIGH",
        confidence=0.985,
    )
    memory_db.add(case)
    memory_db.flush()

    # Evidence preservation record
    orig_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ev = Evidence(
        case_id=case.id,
        evidence_type="raw_eml",
        filename="invoice_urgent.eml",
        path="evidence/MT-2026-000042/raw.eml",
        sha256=orig_sha256,
        size_bytes=4096,
    )
    memory_db.add(ev)

    # Audit events
    aud1 = AuditEvent(case_id=case.id, event_type="CASE_CREATED", description="Case created.")
    aud2 = AuditEvent(case_id=case.id, event_type="ANALYZED", description="Threat analysis completed.")
    memory_db.add_all([aud1, aud2])

    # Rich analysis_json
    analysis_dict = {
        "email": {
            "subject": "Overdue Wire Transfer Notice",
            "from_address": "cfo@spoofed-exec.com",
            "to_address": "finance@targetcorp.com",
            "reply_to": "attacker@freemail.ru",
            "return_path": "bounce@mailer-network.net",
            "date": "Tue, 15 Sep 2026 12:00:00 +0000",
            "message_id": "<msg-0042@spoofed-exec.com>",
            "body_text": "Please initiate urgent wire transfer immediately.",
        },
        "indicators": [
            {"type": "url", "value": "http://malicious-portal.com/login"},
            {"type": "domain", "value": "malicious-portal.com"},
            {"type": "ip", "value": "198.51.100.42"},
        ],
        "identity": {
            "from_domain": "spoofed-exec.com",
            "reply_to_domain": "freemail.ru",
            "return_path_domain": "mailer-network.net",
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
        },
        "authentication": {
            "spf": "PASS",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "alignment": "FAIL",
            "spf_details": {"status": "PASS"},
            "dkim_details": {"status": "FAIL"},
        },
        "detection": {
            "label": "MALICIOUS",
            "confidence": 0.985,
            "model": "DistilBERT (dataset3_v1.0.0)",
            "version": "1.0.0",
            "threat_score": 95,
        },
        "features": {
            "urgency_detected": True,
            "financial_detected": True,
            "credentials_detected": False,
            "authority_detected": True,
            "secrecy_detected": False,
            "suspicious_links_detected": True,
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
            "url_count": 1,
            "domain_count": 1,
            "ip_count": 1,
        },
        "infrastructure": {
            "source_ip": "198.51.100.42",
            "reverse_dns": "host42.network-relay.net",
            "asn": "AS64496",
            "organization": "Example Autonomous System",
            "country": "Netherlands",
        },
        "dns": {
            "malicious-portal.com": {"records": {"A": ["198.51.100.42"]}, "status": "AVAILABLE"},
        },
        "rdap": {
            "198.51.100.42": {"organization": "Hosting Services B.V.", "network_name": "NET-42", "status": "AVAILABLE"},
        },
        "geoip": {
            "198.51.100.42": {"country": "Netherlands", "city": "Amsterdam", "status": "AVAILABLE"},
        },
        "graph": {
            "node_count": 5,
            "edge_count": 4,
            "nodes": [{"data": {"id": "email_1", "type": "EMAIL", "label": "Subject"}}],
            "edges": [{"data": {"id": "e1", "source": "email_1", "target": "domain_1"}}],
        },
        "correlation": {
            "related_case_ids": ["MT-2026-000010"],
            "shared_indicators": [{"type": "ip", "value": "198.51.100.42"}],
            "relationship_strength": "HIGH",
            "campaign_score": 8,
            "correlation_reasons": ["Shared source IP with case MT-2026-000010"],
        },
        "timeline": [
            {"timestamp": "2026-09-15T12:00:00Z", "event": "Email Received", "source": "MTA Hop 1", "details": "From 198.51.100.42"},
            {"timestamp": "2026-09-15T12:05:00Z", "event": "Forensic Ingestion", "source": "Evidence Store", "details": "SHA-256 preserved"},
        ],
        "risk_contributions": {
            "ai_threat": 25,
            "identity": 18,
            "authentication": 14,
            "url_domain": 12,
            "infrastructure": 10,
            "campaign": 6,
        },
        "explanations": ["Critical DMARC alignment failure", "AI high confidence threat detection"],
        "reasons": [{"rule": "DMARC_FAIL", "points": "+15", "description": "DMARC policy validation failed"}],
    }

    case.analysis_json = json.dumps(analysis_dict)
    memory_db.commit()
    memory_db.refresh(case)
    return case


def test_build_case_report_success(memory_db, populated_case):
    """Verify build_case_report constructs complete structured data model."""
    report = build_case_report(memory_db, populated_case.case_number)

    assert report["case_id"] == "MT-2026-000042"
    assert report["case_status"] == "ANALYZED"
    assert "generation_timestamp" in report

    # 1. Evidence immutability & SHA-256 preservation
    orig_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert report["evidence"]["sha256"] == orig_sha256
    assert report["evidence"]["original_filename"] == "invoice_urgent.eml"
    assert len(report["evidence"]["chain_of_custody"]) == 1
    assert report["evidence"]["chain_of_custody"][0]["sha256"] == orig_sha256

    # 2. Email details
    assert report["email"]["subject"] == "Overdue Wire Transfer Notice"
    assert report["email"]["from"] == "cfo@spoofed-exec.com"
    assert report["email"]["reply_to"] == "attacker@freemail.ru"

    # 3. Forensics & Identity
    assert "198.51.100.42" in report["forensics"]["extracted_ips"]
    assert report["forensics"]["identity_consistency"]["reply_to_mismatch"] is True

    # 4. Authentication
    assert report["authentication"]["spf"] == "PASS"
    assert report["authentication"]["dkim"] == "FAIL"
    assert report["authentication"]["dmarc"] == "FAIL"
    assert report["authentication"]["overall_alignment"] == "FAIL"

    # 5. AI Detection
    assert report["ai"]["classification"] == "MALICIOUS"
    assert report["ai"]["confidence"] == 0.985
    assert "DistilBERT" in report["ai"]["model"]

    # 6. Forensic Features
    assert report["features"]["urgency"] is True
    assert report["features"]["financial"] is True
    assert report["features"]["suspicious_links"] is True

    # 7. Infrastructure Intelligence
    assert report["infrastructure"]["source_ip"] == "198.51.100.42"
    assert report["infrastructure"]["country"] == "Netherlands"
    assert report["infrastructure"]["organization"] == "Hosting Services B.V."

    # 8. Relationship Graph
    assert report["graph"]["node_count"] == 5
    assert report["graph"]["edge_count"] == 4

    # 9. Campaign Correlation
    assert report["correlation"]["related_cases"] == ["MT-2026-000010"]
    assert report["correlation"]["relationship_strength"] == "HIGH"
    assert report["correlation"]["campaign_score"] == 8

    # 10. Timeline
    assert len(report["timeline"]) == 2
    assert report["timeline"][0]["event"] == "Email Received"

    # 11. Risk & Contributions
    assert report["risk"]["score"] == 85
    assert report["risk"]["level"] == "HIGH"
    assert report["risk"]["contributions"]["ai_threat"] == 25
    assert report["risk"]["contributions"]["identity"] == 18
    assert report["risk"]["contributions"]["authentication"] == 14
    assert report["risk"]["contributions"]["campaign"] == 6

    # 12. Audit events
    assert len(report["audit"]) == 2

    # 13. Safeguard disclaimer & Analytical conclusion
    assert "IP Geolocation is approximate" in report["forensic_disclaimer"]
    assert "does not prove human identity" in report["forensic_disclaimer"]

    conclusion = report["conclusion"]
    assert "MALICIOUS" in conclusion
    assert "DMARC alignment failure" in conclusion
    assert "Reply-To destination inconsistency" in conclusion
    assert "Observed source infrastructure (198.51.100.42)" in conclusion


def test_build_case_report_nonexistent(memory_db):
    """Verify build_case_report raises ValueError for invalid case identifier."""
    with pytest.raises(ValueError) as exc_info:
        build_case_report(memory_db, "MT-2026-999999")
    assert "was not found" in str(exc_info.value)


def test_forensic_conclusion_safeguards():
    """Verify forensic conclusion language adheres strictly to observed evidence safeguards."""
    sample_report = {
        "ai": {"classification": "MALICIOUS", "confidence": 0.95},
        "risk": {"score": 75, "level": "HIGH"},
        "authentication": {"overall_alignment": "FAIL"},
        "features": {"reply_to_mismatch": True, "urgency": True},
        "infrastructure": {"source_ip": "203.0.113.5", "geoip": {"country": "Germany"}},
        "correlation": {"related_cases": ["MT-001"], "relationship_strength": "MEDIUM"},
    }
    conclusion = generate_forensic_conclusion(sample_report)

    # Required forensic safety language
    assert "Observed source infrastructure" in conclusion
    assert "IP Geolocation" in conclusion
    assert "potential campaign relationship" in conclusion

    # Prohibited speculative assertions
    assert "attacker lives at" not in conclusion.lower()
    assert "exact attacker location" not in conclusion.lower()
    assert "same human attacker" not in conclusion.lower()
    assert "attacker identity confirmed" not in conclusion.lower()
