"""
Unit tests for Phase 9 PDF Forensic Report Generator.
Validates ReportLab document creation, %PDF- header presence,
file output persistence, and error-free rendering of all report sections.
"""

from pathlib import Path
import pytest

from app.reports.pdf_report import generate_pdf_report


@pytest.fixture
def comprehensive_report_dict():
    return {
        "report_id": "REP-MT-2026-000042",
        "generation_timestamp": "2026-09-15T12:30:00+00:00",
        "case_id": "MT-2026-000042",
        "case_status": "ANALYZED",
        "created_at": "2026-09-15T12:00:00+00:00",
        "updated_at": "2026-09-15T12:20:00+00:00",
        "email": {
            "subject": "URGENT: Outstanding Vendor Invoice Remittance Required Immediately",
            "from": "CEO Executive <ceo@spoofed-target.com>",
            "to": "Accounting Team <accounting@targetcorp.com>",
            "reply_to": "attacker-inbox@offshore-mail.ru",
            "return_path": "relay@bulletproof-servers.net",
            "date": "Tue, 15 Sep 2026 11:58:00 +0000",
            "message_id": "<202609151158.42@spoofed-target.com>",
            "body_preview": "Please find attached the revised banking coordinates for wire settlement.",
        },
        "evidence": {
            "original_filename": "urgent_vendor_invoice.eml",
            "file_size": 4096,
            "sha256": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
            "chain_of_custody": [
                {
                    "evidence_type": "raw_eml",
                    "filename": "urgent_vendor_invoice.eml",
                    "sha256": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
                    "size_bytes": 4096,
                    "preservation_status": "SECURED_IMMUTABLE",
                    "created_at": "2026-09-15T12:01:00Z",
                }
            ],
        },
        "forensics": {
            "extracted_urls": ["http://payment-portal.ru/verify", "http://invoice-download.net/doc"],
            "extracted_domains": ["payment-portal.ru", "invoice-download.net"],
            "extracted_ips": ["198.51.100.77"],
            "received_hops": ["from host1 by relay1", "from relay1 by mail.target.com"],
            "identity_consistency": {
                "from_domain": "spoofed-target.com",
                "reply_to_domain": "offshore-mail.ru",
                "return_path_domain": "bulletproof-servers.net",
                "reply_to_mismatch": True,
                "return_path_mismatch": True,
            },
        },
        "authentication": {
            "spf": "PASS",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "spf_alignment": "PASS",
            "dkim_alignment": "FAIL",
            "overall_alignment": "FAIL",
        },
        "ai": {
            "model": "DistilBERT (dataset3_v1.0.0)",
            "version": "1.0.0",
            "classification": "MALICIOUS",
            "confidence": 0.985,
            "threat_score": 95,
        },
        "features": {
            "urgency": True,
            "financial": True,
            "credentials": False,
            "authority": True,
            "secrecy": True,
            "suspicious_links": True,
            "reply_to_mismatch": True,
            "return_path_mismatch": True,
            "url_count": 2,
            "domain_count": 2,
            "ip_count": 1,
        },
        "infrastructure": {
            "source_ip": "198.51.100.77",
            "reverse_dns": "host77.offshore-net.is",
            "asn": "AS42424",
            "organization": "Offshore Cloud Infrastructure",
            "network_name": "NET-OFFSHORE",
            "country": "Iceland",
            "city": "Reykjavik",
            "infrastructure_score": 12,
            "observed_infrastructure_evidence": "Observed routing host 198.51.100.77 (Offshore Cloud)",
            "dns": {"payment-portal.ru": {"records": {"A": ["198.51.100.77"]}, "status": "AVAILABLE"}},
            "rdap": {"organization": "Offshore Cloud Infrastructure"},
            "geoip": {"country": "Iceland"},
        },
        "graph": {
            "node_count": 8,
            "edge_count": 7,
        },
        "correlation": {
            "related_cases": ["MT-2026-000010", "MT-2026-000018"],
            "shared_indicators": [{"type": "ip", "value": "198.51.100.77"}],
            "relationship_strength": "HIGH",
            "campaign_score": 9,
            "correlation_reasons": ["Shared source IP with 2 existing cases"],
        },
        "timeline": [
            {"timestamp": "2026-09-15 11:58:00 UTC", "event": "Email Dispatched", "source": "198.51.100.77", "details": "Relayed via offshore MTA"},
            {"timestamp": "2026-09-15 12:00:10 UTC", "event": "Ingested by Platform", "source": "Evidence Store", "details": "SHA-256 fingerprint verified"},
        ],
        "risk": {
            "score": 88,
            "level": "CRITICAL",
            "confidence": 0.985,
            "contributions": {
                "ai_threat": 25,
                "identity": 20,
                "authentication": 15,
                "url_domain": 10,
                "infrastructure": 10,
                "campaign": 8,
            },
            "reasons": [{"rule": "DMARC_ALIGNMENT_FAIL", "points": "+15", "description": "DMARC alignment validation failed"}],
            "explanations": ["Sequence model flagged malicious wire fraud patterns with 98.5% confidence."],
        },
        "audit": [
            {"event_type": "CASE_CREATED", "description": "Case MT-2026-000042 created", "created_at": "2026-09-15T12:00:00Z"},
            {"event_type": "ANALYZED", "description": "Analysis completed with score 88", "created_at": "2026-09-15T12:20:00Z"},
        ],
        "forensic_disclaimer": "Technical Note: IP Geolocation is approximate and does not prove human identity.",
        "conclusion": "MAILTRACE AI evaluated this email as CRITICAL RISK (88/100). Observed source infrastructure indicates offshore routing with severe identity mismatch.",
    }


def test_generate_pdf_report_bytes(comprehensive_report_dict):
    """Verify generate_pdf_report produces a valid PDF file stream."""
    pdf_bytes = generate_pdf_report(comprehensive_report_dict)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000  # Multi-page structured PDF

    # PDF standard magic bytes
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_file_output(tmp_path, comprehensive_report_dict):
    """Verify generate_pdf_report correctly persists output to the specified filesystem path."""
    target_pdf = tmp_path / "reports" / "MT-2026-000042" / "forensic_report.pdf"
    assert not target_pdf.exists()

    pdf_bytes = generate_pdf_report(comprehensive_report_dict, output_path=target_pdf)
    assert target_pdf.exists()
    assert target_pdf.is_file()

    disk_bytes = target_pdf.read_bytes()
    assert disk_bytes == pdf_bytes
    assert disk_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_empty_optional_fields():
    """Verify PDF rendering handles sparse or minimally populated cases gracefully."""
    minimal_report = {
        "case_id": "MT-2026-000099",
        "case_status": "ANALYZED",
        "email": {},
        "evidence": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "forensics": {},
        "authentication": {},
        "ai": {},
        "features": {},
        "infrastructure": {},
        "graph": {},
        "correlation": {},
        "timeline": [],
        "risk": {"score": 10, "level": "LOW"},
        "audit": [],
    }

    pdf_bytes = generate_pdf_report(minimal_report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
