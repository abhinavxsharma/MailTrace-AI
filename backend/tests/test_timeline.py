"""
Tests for Phase 7 forensic timeline reconstruction.
Verifies chronological event generation, timestamp parsing, and event source attribution.
"""

from datetime import datetime, timezone
import pytest

from app.graph.timeline import build_case_timeline, _parse_rfc2822_date
from app.schemas.timeline import TimelineItem


def test_parse_rfc2822_date_valid():
    """Verify standard email RFC 2822 date conversion to ISO-8601 UTC."""
    date_str = "Thu, 03 Sep 2026 10:19:12 +0000"
    iso_date = _parse_rfc2822_date(date_str)
    assert iso_date.startswith("2026-09-03T10:19:12")


def test_parse_rfc2822_date_empty_and_invalid():
    """Verify safe fallback for None or malformed date strings."""
    assert _parse_rfc2822_date(None) is None
    assert _parse_rfc2822_date("") is None
    assert _parse_rfc2822_date("InvalidDateString") == "InvalidDateString"


def test_build_case_timeline_chronological_ordering():
    """Verify that email header date precedes subsequent forensic milestones."""
    case_data = {
        "email": {
            "date": "Mon, 01 Sep 2026 08:00:00 +0000",
            "from_address": "attacker@spoofed.example",
            "subject": "Wire Transfer Immediate Attention",
        },
        "infrastructure": {
            "source_ip": "198.51.100.42",
            "organization": "Example Cloud AS",
            "country": "DE",
        },
    }

    class MockAuditEvent:
        def __init__(self, event_type, created_at, description):
            self.event_type = event_type
            self.created_at = created_at
            self.description = description

    audit_events = [
        MockAuditEvent(
            "EVIDENCE_PRESERVED",
            datetime(2026, 9, 1, 8, 30, 0, tzinfo=timezone.utc),
            "Raw evidence secured with SHA-256 fingerprint",
        ),
        MockAuditEvent(
            "VERIFIED",
            datetime(2026, 9, 1, 8, 30, 5, tzinfo=timezone.utc),
            "SPF/DKIM/DMARC verification completed",
        ),
        MockAuditEvent(
            "ANALYZED",
            datetime(2026, 9, 1, 8, 30, 10, tzinfo=timezone.utc),
            "AI threat detection completed",
        ),
    ]

    correlation_result = {
        "related_case_ids": ["MT-2026-000099"],
        "shared_indicators": [{"type": "source_ip", "value": "198.51.100.42"}],
    }

    timeline = build_case_timeline(
        case_data=case_data,
        audit_events=audit_events,
        correlation_result=correlation_result,
    )

    assert len(timeline) >= 5

    # Check event order
    event_names = [item["event"] for item in timeline]
    assert event_names[0] == "EMAIL_RECEIVED"
    assert "EVIDENCE_PRESERVED" in event_names
    assert "AUTHENTICATION_VERIFIED" in event_names
    assert "AI_THREAT_ANALYZED" in event_names
    assert "INFRASTRUCTURE_ENRICHED" in event_names
    assert "CAMPAIGN_CORRELATED" in event_names

    # Check timestamps are ascending
    timestamps = [item["timestamp"] for item in timeline]
    assert timestamps == sorted(timestamps)

    # Validate against Pydantic schema
    for item in timeline:
        validated = TimelineItem(**item)
        assert validated.event is not None
        assert validated.timestamp is not None
        assert validated.source is not None


def test_build_case_timeline_empty_case():
    """Verify that an empty case produces empty list without raising exceptions."""
    timeline = build_case_timeline({})
    assert timeline == []
