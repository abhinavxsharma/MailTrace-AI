"""
Tests for Phase 7 cross-case campaign correlation engine.
Verifies indicator matching, deterministic strength scoring, forensic wording,
and false-positive prevention on unrelated cases.
"""

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.case import Case
from app.graph.correlation import correlate_case, evaluate_campaign_score, _extract_case_indicators


@pytest.fixture
def in_memory_db():
    """Isolated in-memory SQLite database for deterministic cross-case correlation tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_correlation_reply_to_match(in_memory_db):
    """Verify that two cases sharing a distinctive Reply-To address correlate with high/medium strength."""
    case1 = Case(
        case_number="MT-2026-0001",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "billing@supplier-portal.com",
                "reply_to": "attacker-dropzone@external-mail.org",
                "return_path": "bounce@supplier-portal.com",
            },
            "infrastructure": {"source_ip": "198.51.100.10"},
            "indicators": [],
        })
    )
    case2 = Case(
        case_number="MT-2026-0002",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "cfo@other-company.org",
                "reply_to": "attacker-dropzone@external-mail.org",
                "return_path": "bounce@other-company.org",
            },
            "infrastructure": {"source_ip": "203.0.113.88"},
            "indicators": [],
        })
    )
    in_memory_db.add_all([case1, case2])
    in_memory_db.commit()

    result = correlate_case(in_memory_db, case1)

    assert "MT-2026-0002" in result["related_case_ids"]
    assert result["relationship_strength"] in ("MEDIUM", "HIGH")
    assert any(si["type"] == "reply_to" and si["value"] == "attacker-dropzone@external-mail.org" for si in result["shared_indicators"])

    # Forensic wording verification
    for reason in result["correlation_reasons"]:
        assert "Potential Campaign Relationship" in reason
        assert "attacker" not in reason.lower() or "potential" in reason.lower()


def test_correlation_shared_infrastructure_ip_and_domain(in_memory_db):
    """Verify correlation when cases share source IP and malicious landing domain."""
    case1 = Case(
        case_number="MT-2026-0010",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "docusign@verify-service.net",
                "reply_to": "docusign@verify-service.net",
            },
            "infrastructure": {"source_ip": "198.51.100.42"},
            "indicators": [
                {"type": "domain", "value": "portal-credential-harvest.biz"},
            ],
        })
    )
    case2 = Case(
        case_number="MT-2026-0011",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "service@account-notice.info",
                "reply_to": "service@account-notice.info",
            },
            "infrastructure": {"source_ip": "198.51.100.42"},
            "indicators": [
                {"type": "url", "value": "https://portal-credential-harvest.biz/login"},
            ],
        })
    )
    in_memory_db.add_all([case1, case2])
    in_memory_db.commit()

    result = correlate_case(in_memory_db, case1)

    assert "MT-2026-0011" in result["related_case_ids"]
    assert result["relationship_strength"] == "HIGH"
    assert result["campaign_score"] >= 8

    # Ensure IP and domain are in shared indicators
    types_found = {si["type"] for si in result["shared_indicators"]}
    assert "source_ip" in types_found
    assert "domain" in types_found


def test_correlation_unrelated_cases_produce_zero_campaign():
    """Verify completely independent, benign, or different threat cases do not falsely correlate."""
    case1 = Case(
        case_number="MT-2026-0020",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "news@tech-insights.com",
                "reply_to": "news@tech-insights.com",
                "return_path": "bounce@tech-insights.com",
            },
            "infrastructure": {"source_ip": "192.0.2.1"},
            "indicators": [{"type": "domain", "value": "tech-insights.com"}],
        })
    )
    case2 = Case(
        case_number="MT-2026-0021",
        status="ANALYZED",
        analysis_json=json.dumps({
            "email": {
                "from_address": "friend@personal-domain.org",
                "reply_to": "friend@personal-domain.org",
                "return_path": "friend@personal-domain.org",
            },
            "infrastructure": {"source_ip": "192.0.2.99"},
            "indicators": [{"type": "domain", "value": "personal-domain.org"}],
        })
    )

    # In-memory session with both
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    session.add_all([case1, case2])
    session.commit()

    result = correlate_case(session, case1)

    assert result["related_case_ids"] == []
    assert result["shared_indicators"] == []
    assert result["relationship_strength"] == "NONE"
    assert result["correlation_reasons"] == []
    assert result["campaign_score"] == 0
    session.close()


def test_evaluate_campaign_score_deterministic_bounds():
    """Verify campaign score bounds (0-10) and incremental indicator weighting."""
    assert evaluate_campaign_score({}) == 0
    assert evaluate_campaign_score({"shared_indicators": []}) == 0

    # Single domain = 4
    assert evaluate_campaign_score({"shared_indicators": [{"type": "domain", "value": "x.com"}]}) == 4

    # Single Reply-To = 5
    assert evaluate_campaign_score({"shared_indicators": [{"type": "reply_to", "value": "a@b.com"}]}) == 5

    # Source IP + Reply-To = 4 + 5 = 9
    assert evaluate_campaign_score({
        "shared_indicators": [
            {"type": "source_ip", "value": "1.2.3.4"},
            {"type": "reply_to", "value": "a@b.com"},
        ]
    }) == 9

    # Source IP + Reply-To + Domain = 4 + 5 + 4 = 13 -> capped at 10
    assert evaluate_campaign_score({
        "shared_indicators": [
            {"type": "source_ip", "value": "1.2.3.4"},
            {"type": "reply_to", "value": "a@b.com"},
            {"type": "domain", "value": "x.com"},
        ]
    }) == 10
