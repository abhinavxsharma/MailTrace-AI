"""
Tests for cryptographic evidence hashing, preservation, and audit trail logging.
"""

import hashlib
import tempfile
from pathlib import Path
import pytest

from app.evidence.hasher import calculate_sha256
from app.evidence.preservation import preserve_evidence
from app.evidence.audit import record_audit_event
from app.db.session import SessionLocal
from app.models.case import Case


def test_calculate_sha256_deterministic():
    """Verify SHA-256 calculation is deterministic and matches hashlib standard."""
    sample_bytes = b"Forensic email evidence content for testing\r\n"
    expected = hashlib.sha256(sample_bytes).hexdigest()
    result = calculate_sha256(sample_bytes)
    assert result == expected
    assert len(result) == 64
    # Determinism check
    assert calculate_sha256(sample_bytes) == result


def test_calculate_sha256_type_error():
    """Verify calculating hash on non-bytes raises TypeError."""
    with pytest.raises(TypeError):
        calculate_sha256("string not bytes")


def test_preserve_evidence_file_and_hash_integrity():
    """Verify evidence file is saved and hash matches read-back content."""
    sample_bytes = b"From: attacker@example.com\r\nSubject: Test\r\n\r\nEvidence payload"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        stored_path, size, sha256_val = preserve_evidence(
            case_id="MT-TEST-001",
            raw_bytes=sample_bytes,
            filename="raw.eml",
            base_dir=tmp_path,
        )

        assert stored_path.exists()
        assert size == len(sample_bytes)
        assert sha256_val == hashlib.sha256(sample_bytes).hexdigest()
        assert stored_path.read_bytes() == sample_bytes

        # Attempting overwrite without flag should raise FileExistsError
        with pytest.raises(FileExistsError):
            preserve_evidence(
                case_id="MT-TEST-001",
                raw_bytes=sample_bytes,
                filename="raw.eml",
                base_dir=tmp_path,
                overwrite=False,
            )


def test_record_audit_event():
    """Verify audit events are written to the database with timestamps."""
    db = SessionLocal()
    try:
        case = Case(case_number="MT-AUDIT-001", status="UPLOADED")
        db.add(case)
        db.commit()
        db.refresh(case)

        event = record_audit_event(
            db=db,
            case_id=case.id,
            event_type="UPLOADED",
            description="Test upload event description",
        )
        assert event.id is not None
        assert event.event_type == "UPLOADED"
        assert event.created_at is not None

        # Clean up
        db.delete(case)
        db.commit()
    finally:
        db.close()
