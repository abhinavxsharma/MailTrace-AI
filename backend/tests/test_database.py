"""
Tests for database initialization, models, and relationships.
"""

import pytest
from app.db.session import init_db, SessionLocal, engine, Base
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.audit_event import AuditEvent


def test_database_initialization():
    """Verify that tables are created without errors."""
    init_db()
    table_names = engine.dialect.get_table_names(engine.connect())
    assert "cases" in table_names
    assert "evidences" in table_names
    assert "audit_events" in table_names


def test_case_and_evidence_persistence():
    """Verify model persistence and relational cascades."""
    db = SessionLocal()
    try:
        # Create a test case
        case = Case(
            case_number="MT-2026-999001",
            filename="sample.eml",
            original_filename="sample.eml",
            status="UPLOADED",
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        assert case.id is not None
        assert case.case_number == "MT-2026-999001"

        # Add evidence
        evidence = Evidence(
            case_id=case.id,
            evidence_type="raw_eml",
            filename="sample.eml",
            path="evidence/sample.eml",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size_bytes=1024,
        )
        db.add(evidence)

        # Add audit event
        audit = AuditEvent(
            case_id=case.id,
            event_type="TEST_EVENT",
            description="Database test event description",
        )
        db.add(audit)
        db.commit()

        # Query and verify relationships
        queried = db.query(Case).filter(Case.case_number == "MT-2026-999001").first()
        assert queried is not None
        assert len(queried.evidences) == 1
        assert queried.evidences[0].sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert len(queried.audit_events) == 1
        assert queried.audit_events[0].event_type == "TEST_EVENT"

        # Clean up test row
        db.delete(queried)
        db.commit()
    finally:
        db.close()
