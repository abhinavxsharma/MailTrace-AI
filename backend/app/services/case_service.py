"""
Case management service handling case creation, retrieval, evidence linkage, and status updates.
"""

import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.audit_event import AuditEvent
from app.schemas.case import CaseStatus
from app.schemas.analysis import CaseDetailResponse
from app.schemas.email import EmailSchema
from app.schemas.verification import AuthenticationSchema, IdentitySchema
from app.schemas.infrastructure import InfrastructureSchema
from app.schemas.risk import RiskDimensions, RiskClassification
from app.schemas.graph import GraphResponse


def generate_case_number(db: Session) -> str:
    """Generate a unique sequential case number formatted as MT-2026-XXXXXX."""
    max_id = db.query(func.max(Case.id)).scalar() or 0
    seq = max_id + 1
    while True:
        candidate = f"MT-2026-{seq:06d}"
        exists = db.query(Case).filter(Case.case_number == candidate).first()
        if not exists:
            return candidate
        seq += 1


def create_case(
    db: Session,
    filename: Optional[str] = None,
    original_filename: Optional[str] = None,
) -> Case:
    """Create a new case record and log its initial creation audit event."""
    case_number = generate_case_number(db)
    case = Case(
        case_number=case_number,
        filename=filename,
        original_filename=original_filename,
        status=CaseStatus.UPLOADED.value,
    )
    db.add(case)
    db.flush()

    audit = AuditEvent(
        case_id=case.id,
        event_type="CASE_CREATED",
        description=f"Case {case.case_number} registered with status UPLOADED.",
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case


def get_case(db: Session, case_id: str) -> Optional[Case]:
    """Retrieve a case by case_number (e.g. MT-2026-000001) or internal integer ID."""
    if case_id.isdigit():
        case = db.query(Case).filter((Case.case_number == case_id) | (Case.id == int(case_id))).first()
    else:
        case = db.query(Case).filter(Case.case_number == case_id).first()
    return case


def attach_evidence(
    db: Session,
    case: Case,
    filename: str,
    path: str,
    sha256: str,
    size_bytes: int,
    evidence_type: str = "raw_eml",
) -> Evidence:
    """Attach preserved evidence record to the case and log audit event."""
    evidence = Evidence(
        case_id=case.id,
        evidence_type=evidence_type,
        filename=filename,
        path=str(path),
        sha256=sha256,
        size_bytes=size_bytes,
    )
    db.add(evidence)
    db.flush()

    audit = AuditEvent(
        case_id=case.id,
        event_type="EVIDENCE_PRESERVED",
        description=f"Preserved {evidence_type} artifact '{filename}' (SHA-256: {sha256}).",
    )
    db.add(audit)
    db.commit()
    db.refresh(evidence)
    return evidence


def update_case_status(
    db: Session,
    case: Case,
    status: CaseStatus,
    description: Optional[str] = None,
) -> Case:
    """Update case status and append an audit event."""
    case.status = status.value if hasattr(status, "value") else str(status)
    audit = AuditEvent(
        case_id=case.id,
        event_type="STATUS_UPDATED",
        description=description or f"Case status advanced to {case.status}.",
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case


def update_case_analysis(
    db: Session,
    case: Case,
    risk_score: Optional[int] = None,
    classification: Optional[str] = None,
    confidence: Optional[float] = None,
    analysis_data: Optional[dict] = None,
) -> Case:
    """Update case risk scoring and serialized analysis output."""
    if risk_score is not None:
        case.risk_score = risk_score
    if classification is not None:
        case.classification = classification
    if confidence is not None:
        case.confidence = confidence
    if analysis_data is not None:
        case.analysis_json = json.dumps(analysis_data)

    audit = AuditEvent(
        case_id=case.id,
        event_type="ANALYSIS_UPDATED",
        description=f"Analysis updated. Risk score: {risk_score}, Classification: {classification}.",
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case


def case_to_response(case: Case) -> CaseDetailResponse:
    """Convert a database Case model into the canonical CaseDetailResponse contract."""
    data: Dict[str, Any] = {}
    if case.analysis_json:
        try:
            data = json.loads(case.analysis_json)
        except Exception:
            data = {}

    classification_val = None
    raw_class = case.classification or data.get("classification")
    if raw_class:
        try:
            classification_val = RiskClassification(raw_class)
        except ValueError:
            classification_val = None

    risk_score_val = case.risk_score if case.risk_score is not None else data.get("risk_score")
    confidence_val = case.confidence if case.confidence is not None else data.get("confidence")

    # Derive evidence payload if not explicitly present in analysis data
    evidence_payload = data.get("evidence", {})
    if not evidence_payload and case.evidences:
        latest = case.evidences[-1]
        evidence_payload = {
            "sha256": latest.sha256,
            "size_bytes": latest.size_bytes,
            "filename": latest.filename,
            "path": latest.path,
        }

    return CaseDetailResponse(
        case_id=case.case_number,
        status=CaseStatus(case.status) if case.status in [s.value for s in CaseStatus] else CaseStatus.UPLOADED,
        risk_score=risk_score_val,
        classification=classification_val,
        confidence=confidence_val,
        email=data.get("email", EmailSchema()),
        authentication=data.get("authentication", AuthenticationSchema()),
        identity=data.get("identity", IdentitySchema()),
        indicators=data.get("indicators", []),
        infrastructure=data.get("infrastructure", InfrastructureSchema()),
        detection=data.get("detection", None),
        risk_dimensions=data.get("risk_dimensions", RiskDimensions()),
        reasons=data.get("reasons", []),
        graph=data.get("graph", GraphResponse()),
        evidence=evidence_payload,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )
