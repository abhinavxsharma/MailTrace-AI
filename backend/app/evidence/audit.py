"""
Audit trail module for recording immutable forensic chain-of-custody events.
"""

from sqlalchemy.orm import Session
from app.models.audit_event import AuditEvent


def record_audit_event(
    db: Session,
    case_id: int,
    event_type: str,
    description: str,
) -> AuditEvent:
    """
    Append an immutable audit entry to the case audit log.

    Args:
        db: Active SQLAlchemy session.
        case_id: Database internal ID of the case.
        event_type: Event classification string (e.g. UPLOADED, PARSED).
        description: Plain text explanation of the event.

    Returns:
        Persisted AuditEvent instance.
    """
    event = AuditEvent(
        case_id=case_id,
        event_type=event_type,
        description=description,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
