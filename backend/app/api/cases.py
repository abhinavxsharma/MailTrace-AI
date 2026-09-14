"""
Case management API endpoints.
Provides case upload, parsing orchestration, verification workflow, metadata queries, and indicator retrieval.
"""

import json
from pathlib import Path
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.case import (
    CaseStatus,
    CaseTestResponse,
    CaseTestCreate,
    CaseUploadResponse,
    CaseUploadEvidence,
)
from app.schemas.verification import (
    CaseVerifyResponse,
    AuthenticationSchema,
    IdentitySchema,
)
from app.schemas.email import EmailSchema
from app.schemas.indicator import IndicatorSchema
from app.schemas.analysis import CaseDetailResponse
from app.services.case_service import (
    create_case,
    get_case,
    attach_evidence,
    update_case_status,
    case_to_response,
)
from app.evidence.hasher import calculate_sha256
from app.evidence.preservation import preserve_evidence
from app.evidence.audit import record_audit_event
from app.forensics.parser import parse_email_bytes
from app.forensics.headers import analyze_identity_consistency, extract_core_headers
from app.forensics.received import analyze_received_chain
from app.forensics.indicators import extract_indicators
from app.forensics.authentication import verify_email_authentication

router = APIRouter(prefix="/cases", tags=["Cases"])

# Maximum allowed file size: 10 MB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024


@router.post(
    "/upload",
    response_model=CaseUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload raw .eml file and run forensic ingestion",
    description="Ingests a raw .eml email, calculates SHA-256 fingerprint, preserves evidence, and performs initial forensic parsing.",
)
async def upload_case_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Ingest a real .eml file, preserve original bytes, and extract initial forensic structures.
    """
    filename = file.filename or "unknown.eml"

    # 1. Validate file extension (case-insensitive)
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Only .eml files are accepted for forensic analysis.",
        )

    # 2. Read raw bytes and validate size
    try:
        raw_bytes = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}",
        )

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty. A valid .eml file must contain RFC 5322 content.",
        )

    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB.",
        )

    # 3. Calculate deterministic SHA-256 fingerprint
    sha256_hash = calculate_sha256(raw_bytes)

    # 4. Create case in database with initial UPLOADED status
    case = create_case(
        db=db,
        filename=filename,
        original_filename=filename,
    )

    # 5. Preserve evidence to filesystem at evidence/{case_id}/raw.eml
    try:
        stored_path, size_bytes, verified_sha256 = preserve_evidence(
            case_id=case.case_number,
            raw_bytes=raw_bytes,
            filename="raw.eml",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to preserve evidence artifact: {str(e)}",
        )

    # 6. Record Evidence database entry and UPLOADED audit event
    attach_evidence(
        db=db,
        case=case,
        filename=filename,
        path=str(stored_path),
        sha256=verified_sha256,
        size_bytes=size_bytes,
        evidence_type="raw_eml",
    )
    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="UPLOADED",
        description=f"Original email file '{filename}' preserved with SHA-256 {verified_sha256}.",
    )

    # 7. Perform forensic email parsing
    try:
        email_schema, attachments, raw_headers = parse_email_bytes(raw_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse email structure: {str(e)}",
        )

    # 8. Forensic extraction: headers, identity, received chain, indicators
    core_headers = extract_core_headers(raw_headers)
    identity_schema = analyze_identity_consistency(
        from_header=email_schema.from_address,
        reply_to_header=email_schema.reply_to,
        return_path_header=email_schema.return_path,
    )
    received_data = analyze_received_chain(email_schema.received_headers)
    indicators = extract_indicators(
        subject=email_schema.subject or "",
        body_text=email_schema.body_text or "",
        body_html=email_schema.body_html or "",
        raw_headers=raw_headers,
    )

    # 9. Structure complete analysis payload
    analysis_data = {
        "email": email_schema.model_dump(),
        "core_headers": core_headers,
        "raw_headers": raw_headers,
        "identity": identity_schema.model_dump(),
        "authentication": {
            "spf": "UNKNOWN",
            "dkim": "UNKNOWN",
            "dmarc": "UNKNOWN",
            "alignment": "UNKNOWN",
        },
        "indicators": [ind.model_dump() for ind in indicators],
        "infrastructure": {
            "source_ip": received_data.get("observed_source_ip"),
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "organization": None,
            "network_type": None,
            "rdap_status": "unknown",
            "dns_status": "unknown",
            "geoip_status": "unknown",
        },
        "risk_dimensions": {
            "ai_threat": 0.0,
            "authentication": 0.0,
            "identity_consistency": 0.0,
            "url_risk": 0.0,
            "infrastructure_risk": 0.0,
            "bec_risk": 0.0,
        },
        "reasons": [],
        "graph": {"nodes": [], "edges": []},
        "evidence": {
            "sha256": verified_sha256,
            "size_bytes": size_bytes,
            "filename": filename,
            "path": str(stored_path),
        },
        "attachments_metadata": attachments,
        "received_chain": received_data,
    }

    # 10. Persist analysis JSON, advance status to PARSED, and record audit event
    case.analysis_json = json.dumps(analysis_data)
    update_case_status(
        db=db,
        case=case,
        status=CaseStatus.PARSED,
        description="MIME parsing, identity consistency, and IOC extraction complete.",
    )
    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="PARSED",
        description=f"Forensic extraction completed: {len(indicators)} indicators identified.",
    )

    return CaseUploadResponse(
        case_id=case.case_number,
        status=CaseStatus.PARSED,
        evidence=CaseUploadEvidence(
            sha256=verified_sha256,
            size_bytes=size_bytes,
        ),
    )


@router.post(
    "/{case_id}/verify",
    response_model=CaseVerifyResponse,
    summary="Verify email authentication protocols (SPF, DKIM, DMARC) and identity alignment",
    description="Loads preserved raw .eml evidence, parses declared Authentication-Results, performs active SPF/DKIM verification, evaluates strict and relaxed DMARC alignment, and advances status to VERIFIED.",
)
def verify_case_authentication(
    case_id: str,
    db: Session = Depends(get_db),
):
    """
    Run email verification workflow on a parsed case.
    Evaluates SPF, DKIM, DMARC, alignment, and identity consistency.
    """
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )

    # Must be at least PARSED or already VERIFIED
    if case.status not in (CaseStatus.PARSED.value, CaseStatus.VERIFIED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Case '{case_id}' has status '{case.status}'. Cases must be PARSED before running verification.",
        )

    # Locate raw .eml file
    evidence_path = None
    if case.evidences:
        candidate = Path(case.evidences[0].path)
        if candidate.exists():
            evidence_path = candidate

    if not evidence_path:
        default_path = Path("evidence") / case.case_number / "raw.eml"
        if default_path.exists():
            evidence_path = default_path

    if not evidence_path or not evidence_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Preserved evidence artifact not found for case '{case_id}'.",
        )

    raw_bytes = evidence_path.read_bytes()

    # Load existing parsed analysis data
    analysis_data: Dict[str, Any] = {}
    if case.analysis_json:
        try:
            analysis_data = json.loads(case.analysis_json)
        except Exception:
            analysis_data = {}

    email_dict = analysis_data.get("email", {})
    email_schema = EmailSchema(**email_dict)
    raw_headers = analysis_data.get("raw_headers", {})
    source_ip = analysis_data.get("infrastructure", {}).get("source_ip")

    # Perform authentication verification
    auth_schema = verify_email_authentication(
        raw_bytes=raw_bytes,
        email_schema=email_schema,
        raw_headers=raw_headers,
        source_ip=source_ip,
    )

    # Re-evaluate identity with full domain/mismatch attributes
    identity_schema = analyze_identity_consistency(
        from_header=email_schema.from_address,
        reply_to_header=email_schema.reply_to,
        return_path_header=email_schema.return_path,
    )

    # Update analysis data
    analysis_data["authentication"] = auth_schema.model_dump()
    analysis_data["identity"] = identity_schema.model_dump()
    case.analysis_json = json.dumps(analysis_data)

    # Advance status to VERIFIED
    update_case_status(
        db=db,
        case=case,
        status=CaseStatus.VERIFIED,
        description=f"Authentication verification complete. SPF: {auth_schema.spf.value}, DKIM: {auth_schema.dkim.value}, DMARC: {auth_schema.dmarc.value}, Alignment: {auth_schema.alignment.value}.",
    )
    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="VERIFIED",
        description=f"SPF: {auth_schema.spf.value} | DKIM: {auth_schema.dkim.value} | DMARC: {auth_schema.dmarc.value} | Alignment: {auth_schema.alignment.value}",
    )

    return CaseVerifyResponse(
        case_id=case.case_number,
        status=CaseStatus.VERIFIED,
        authentication=auth_schema,
        identity=identity_schema,
    )


@router.get(
    "/{case_id}/authentication",
    response_model=AuthenticationSchema,
    summary="Get authentication verification details for a case",
    description="Returns declared, active verified, and alignment evaluation for SPF, DKIM, and DMARC.",
)
def get_case_authentication(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve normalized authentication verification object for a case."""
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if not case.analysis_json:
        return AuthenticationSchema()
    try:
        data = json.loads(case.analysis_json)
        auth_data = data.get("authentication", {})
        return AuthenticationSchema(**auth_data)
    except Exception:
        return AuthenticationSchema()


@router.post(
    "/test",
    response_model=CaseTestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a synthetic test case",
    description="Initializes a new case record with test metadata for contract and pipeline validation.",
)
def create_test_case(
    payload: CaseTestCreate = CaseTestCreate(),
    db: Session = Depends(get_db),
):
    """Create a test case with default UPLOADED status."""
    case = create_case(
        db=db,
        filename="test_synthetic_sample.eml",
        original_filename="test_synthetic_sample.eml",
    )
    return CaseTestResponse(
        case_id=case.case_number,
        status=case.status,
    )


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get case details and forensic analysis",
    description="Returns the canonical case analysis contract matching the shared specification.",
)
def get_case_detail(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full case details by case number (e.g. MT-2026-000001) or internal ID."""
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    return case_to_response(case)


@router.get(
    "/{case_id}/headers",
    response_model=Dict[str, Any],
    summary="Get normalized and raw headers for a case",
    description="Returns extracted RFC 5322 forensic headers and repeated Received chains.",
)
def get_case_headers(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve structured headers extracted during email ingestion."""
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if not case.analysis_json:
        return {}
    try:
        data = json.loads(case.analysis_json)
        return data.get("core_headers", {})
    except Exception:
        return {}


@router.get(
    "/{case_id}/indicators",
    response_model=List[IndicatorSchema],
    summary="Get extracted IOC indicators for a case",
    description="Returns deduplicated URLs, domains, and IP addresses extracted from headers and body.",
)
def get_case_indicators(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve indicators of compromise extracted from the email."""
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if not case.analysis_json:
        return []
    try:
        data = json.loads(case.analysis_json)
        raw_indicators = data.get("indicators", [])
        return [IndicatorSchema(**item) for item in raw_indicators]
    except Exception:
        return []


@router.get(
    "/{case_id}/evidence",
    response_model=List[Dict[str, Any]],
    summary="Get evidence chain-of-custody artifacts for a case",
    description="Returns preserved files, cryptographic hashes, and storage paths.",
)
def get_case_evidence(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve evidence chain-of-custody records for the case."""
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    return [
        {
            "id": ev.id,
            "evidence_type": ev.evidence_type,
            "filename": ev.filename,
            "path": ev.path,
            "sha256": ev.sha256,
            "size_bytes": ev.size_bytes,
            "created_at": ev.created_at.isoformat() if ev.created_at else None,
        }
        for ev in case.evidences
    ]
