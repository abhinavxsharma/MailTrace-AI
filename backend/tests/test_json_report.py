"""
Unit tests for Phase 9 JSON Forensic Report Generator.
Validates machine-readable output serialization, deterministic structure,
disk persistence, and evidence preservation.
"""

import json
from pathlib import Path
import pytest

from app.reports.json_report import generate_json_report


@pytest.fixture
def sample_report_payload():
    return {
        "report_id": "REP-MT-2026-000042",
        "case_id": "MT-2026-000042",
        "case_status": "ANALYZED",
        "email": {
            "subject": "Wire Transfer Request",
            "from": "cfo@company.com",
            "to": "accounting@company.com",
        },
        "evidence": {
            "original_filename": "sample.eml",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "file_size": 2048,
        },
        "authentication": {
            "spf": "PASS",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "overall_alignment": "FAIL",
        },
        "ai": {
            "classification": "MALICIOUS",
            "confidence": 0.97,
            "model": "DistilBERT (dataset3_v1.0.0)",
        },
        "risk": {
            "score": 82,
            "level": "HIGH",
            "contributions": {
                "ai_threat": 25,
                "identity": 18,
                "authentication": 14,
                "url_domain": 10,
                "infrastructure": 10,
                "campaign": 5,
            },
        },
    }


def test_generate_json_report_string(sample_report_payload):
    """Verify generate_json_report produces valid, pretty-printed JSON."""
    json_str = generate_json_report(sample_report_payload)
    assert isinstance(json_str, str)
    assert len(json_str) > 0

    # Ensure it deserializes cleanly back to the identical dictionary
    parsed = json.loads(json_str)
    assert parsed["case_id"] == "MT-2026-000042"
    assert parsed["evidence"]["sha256"] == "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
    assert parsed["ai"]["classification"] == "MALICIOUS"
    assert parsed["risk"]["score"] == 82


def test_generate_json_report_file_persistence(tmp_path, sample_report_payload):
    """Verify generate_json_report safely writes output to disk if output_path is provided."""
    target_file = tmp_path / "reports" / "MT-2026-000042" / "forensic_report.json"
    assert not target_file.exists()

    json_str = generate_json_report(sample_report_payload, output_path=target_file)
    assert target_file.exists()
    assert target_file.is_file()

    disk_content = target_file.read_text(encoding="utf-8")
    assert disk_content == json_str


def test_generate_json_report_deterministic(sample_report_payload):
    """Verify multiple calls produce identical, deterministic JSON representations."""
    res1 = generate_json_report(sample_report_payload)
    res2 = generate_json_report(sample_report_payload)
    assert res1 == res2
