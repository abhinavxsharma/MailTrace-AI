"""
Evidence package for MAILTRACE AI.
"""

from app.evidence.hasher import calculate_sha256
from app.evidence.preservation import preserve_evidence
from app.evidence.audit import record_audit_event

__all__ = ["calculate_sha256", "preserve_evidence", "record_audit_event"]
