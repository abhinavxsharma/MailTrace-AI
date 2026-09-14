"""
Case database model representing an email forensic investigation.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_number = Column(String(50), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=True)
    original_filename = Column(String(255), nullable=True)
    status = Column(String(50), nullable=False, default="UPLOADED", index=True)
    risk_score = Column(Integer, nullable=True)
    classification = Column(String(50), nullable=True)
    confidence = Column(Float, nullable=True)
    analysis_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    evidences = relationship(
        "Evidence",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="Evidence.id",
    )
    audit_events = relationship(
        "AuditEvent",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="AuditEvent.id",
    )

    def __repr__(self):
        return f"<Case(id={self.id}, case_number='{self.case_number}', status='{self.status}')>"
