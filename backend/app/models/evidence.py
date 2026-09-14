"""
Evidence database model representing preserved files, hashes, and artifacts.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class Evidence(Base):
    __tablename__ = "evidences"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False, default="raw_eml")
    filename = Column(String(255), nullable=False)
    path = Column(String(500), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationship
    case = relationship("Case", back_populates="evidences")

    def __repr__(self):
        return f"<Evidence(id={self.id}, case_id={self.case_id}, type='{self.evidence_type}', sha256='{self.sha256[:8]}...')>"
