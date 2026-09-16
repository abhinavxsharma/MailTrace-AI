"""
Case management API endpoints.
Provides case upload, parsing orchestration, verification workflow, metadata queries, and indicator retrieval.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
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
from app.schemas.risk import CaseAnalyzeResponse
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
from app.detection.classifier import get_classifier, strip_html_tags
from app.detection.features import extract_forensic_features
from app.detection.risk_fusion import fuse_evidence
from app.intelligence import enrich_indicators
from app.graph import build_case_graph, correlate_case, build_case_timeline
from app.reports import build_case_report, generate_json_report, generate_pdf_report

router = APIRouter(prefix="/cases", tags=["Cases"])

# Maximum allowed file size: 10 MB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def validate_case_id(case_id: str) -> str:
    """Validate case identifier to prevent directory traversal or malformed path input."""
    if not case_id or not CASE_ID_PATTERN.match(case_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Case ID format. Must be 1-64 alphanumeric characters, hyphens, or underscores.",
        )
    return case_id


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
    raw_filename = file.filename or "unknown.eml"
    clean_filename = Path(raw_filename.replace("\x00", "")).name
    clean_filename = re.sub(r"[^\w\.\-\s]", "_", clean_filename).strip()
    if not clean_filename or clean_filename == ".eml":
        clean_filename = "evidence.eml"

    # 1. Validate file extension (case-insensitive)
    if not clean_filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Only .eml files are accepted for forensic analysis.",
        )
    filename = clean_filename

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
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )

    # Must be at least PARSED, VERIFIED, ANALYZED, or REPORTED
    if case.status not in (CaseStatus.PARSED.value, CaseStatus.VERIFIED.value, CaseStatus.ANALYZED.value, CaseStatus.REPORTED.value):
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
    validate_case_id(case_id)
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
    "/{case_id}/analyze",
    response_model=CaseAnalyzeResponse,
    summary="Run AI threat detection, forensic feature extraction, and risk fusion",
    description="Analyzes email content using fine-tuned DistilBERT model, extracts linguistic/identity signals, and generates a calibrated 0-100 risk score.",
)
def analyze_case_threat(
    case_id: str,
    db: Session = Depends(get_db),
):
    """
    Run full threat analysis pipeline: AI classification, feature extraction,
    passive infrastructure intelligence, relationship graph, timeline, and risk fusion.
    """
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )

    # Must be at least PARSED, VERIFIED, ANALYZED, or REPORTED
    valid_statuses = (CaseStatus.PARSED.value, CaseStatus.VERIFIED.value, CaseStatus.ANALYZED.value, CaseStatus.REPORTED.value)
    if case.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Case '{case_id}' has status '{case.status}'. Cases must be PARSED before running analysis.",
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

    # Load existing parsed analysis data
    analysis_data: Dict[str, Any] = {}
    if case.analysis_json:
        try:
            analysis_data = json.loads(case.analysis_json)
        except Exception:
            analysis_data = {}

    email_dict = analysis_data.get("email", {})
    email_schema = EmailSchema(**email_dict)
    indicators_raw = analysis_data.get("indicators", [])
    indicators = [IndicatorSchema(**item) for item in indicators_raw]
    raw_headers = analysis_data.get("raw_headers", {})
    source_ip = analysis_data.get("infrastructure", {}).get("source_ip")

    # If authentication hasn't been evaluated yet, evaluate it
    auth_data = analysis_data.get("authentication")
    if not auth_data:
        raw_bytes = evidence_path.read_bytes()
        auth_schema = verify_email_authentication(
            raw_bytes=raw_bytes,
            email_schema=email_schema,
            raw_headers=raw_headers,
            source_ip=source_ip,
        )
        analysis_data["authentication"] = auth_schema.model_dump()
    else:
        auth_schema = AuthenticationSchema(**auth_data)

    # Identity schema
    identity_data = analysis_data.get("identity")
    if not identity_data:
        identity_schema = analyze_identity_consistency(
            from_header=email_schema.from_address,
            reply_to_header=email_schema.reply_to,
            return_path_header=email_schema.return_path,
        )
        analysis_data["identity"] = identity_schema.model_dump()
    else:
        identity_schema = IdentitySchema(**identity_data)

    # 1. AI Threat Classifier
    classifier = get_classifier()
    detection_schema = classifier.classify_email(
        subject=email_schema.subject,
        body_text=email_schema.body_text,
        body_html=email_schema.body_html,
    )

    # Raw model prediction details
    plain_body = email_schema.body_text or (strip_html_tags(email_schema.body_html) if email_schema.body_html else "")
    input_text = f"Subject: {email_schema.subject or ''}\n\n{plain_body}".strip()
    ai_pred = classifier.predict(input_text)
    ai_confidence = float(ai_pred.get("confidence") or 0.0)

    # 2. Forensic Feature Extraction
    extracted_features = extract_forensic_features(
        email=email_schema,
        indicators=indicators,
        identity=identity_schema,
    )

    # 3. Infrastructure Intelligence Enrichment (DNS, RDAP, GeoIP)
    sender_domain = None
    if email_schema.from_address and "@" in email_schema.from_address:
        sender_domain = email_schema.from_address.split("@", 1)[1].strip(">").strip()

    infra_intel = enrich_indicators(
        indicators=indicators,
        source_ip=source_ip,
        sender_domain=sender_domain,
    )

    # 4. Cross-Case Campaign Correlation
    correlation_result = correlate_case(db=db, target_case=case)
    campaign_score = correlation_result.get("campaign_score", 0)

    # 5. Evidence Fusion & Risk Scoring
    fusion_result = fuse_evidence(
        ai_prediction=ai_pred,
        features=extracted_features,
        authentication=auth_schema,
        identity=identity_schema,
        observed_source_ip=source_ip,
        infrastructure_intelligence=infra_intel,
        campaign_correlation=correlation_result,
    )

    risk_score = fusion_result["risk_score"]
    risk_level = fusion_result["risk_level"]
    risk_assessment = fusion_result["risk_assessment"]
    risk_contributions = fusion_result["risk_contributions"]
    infrastructure_score = fusion_result.get("infrastructure_score", 0)
    campaign_score = fusion_result.get("campaign_score", campaign_score)
    explanations = fusion_result["explanations"]

    # 6. Graph Construction (NetworkX Cytoscape format)
    analysis_data["detection"] = detection_schema.model_dump()
    analysis_data["features"] = extracted_features
    analysis_data["infrastructure"] = infra_intel["infrastructure_schema"].model_dump()
    analysis_data["dns"] = infra_intel["dns"]
    analysis_data["rdap"] = infra_intel["rdap"]
    analysis_data["geoip"] = infra_intel["geoip"]
    analysis_data["infrastructure_score"] = infrastructure_score
    analysis_data["correlation"] = correlation_result
    analysis_data["campaign_score"] = campaign_score

    graph_data = build_case_graph(analysis_data, case.case_number)
    timeline_data = build_case_timeline(
        analysis_data,
        audit_events=case.audit_events,
        correlation_result=correlation_result,
    )

    analysis_data["graph"] = graph_data
    analysis_data["timeline"] = timeline_data
    analysis_data["risk_score"] = risk_score
    analysis_data["classification"] = risk_level.value
    analysis_data["confidence"] = ai_confidence
    analysis_data["risk_dimensions"] = risk_assessment.dimensions.model_dump()
    analysis_data["reasons"] = [r.model_dump() for r in risk_assessment.reasons]
    analysis_data["risk_contributions"] = risk_contributions
    analysis_data["explanations"] = explanations

    # Update Case database model
    case.risk_score = risk_score
    case.classification = risk_level.value
    case.confidence = ai_confidence
    case.analysis_json = json.dumps(analysis_data)
    db.commit()

    # Advance status to ANALYZED
    update_case_status(
        db=db,
        case=case,
        status=CaseStatus.ANALYZED,
        description=f"Analysis complete. Score: {risk_score} ({risk_level.value}), AI: {ai_pred.get('label')}.",
    )
    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="ANALYZED",
        description=f"Risk: {risk_score} | Level: {risk_level.value} | Model: {ai_pred.get('model')} | Confidence: {ai_confidence:.4f}",
    )

    return CaseAnalyzeResponse(
        case_id=case.case_number,
        status=CaseStatus.ANALYZED.value,
        ai_prediction=ai_pred,
        ai_confidence=ai_confidence,
        extracted_features=extracted_features,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_contributions=risk_contributions,
        infrastructure=infra_intel["infrastructure_schema"].model_dump(),
        dns=infra_intel["dns"],
        rdap=infra_intel["rdap"],
        geoip=infra_intel["geoip"],
        infrastructure_score=infrastructure_score,
        graph=graph_data,
        correlation=correlation_result,
        timeline=timeline_data,
        campaign_score=campaign_score,
        explanations=explanations,
    )


@router.get(
    "/{case_id}/graph",
    response_model=Dict[str, Any],
    summary="Get forensic relationship graph for a case",
    description="Returns Cytoscape.js compatible nodes and edges representing email entities, domains, IPs, and infrastructure.",
)
def get_case_graph(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve Cytoscape.js relationship graph for a case."""
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if not case.analysis_json:
        return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0}
    try:
        data = json.loads(case.analysis_json)
        return data.get("graph") or build_case_graph(data, case.case_number)
    except Exception:
        return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0}


@router.get(
    "/{case_id}/timeline",
    response_model=List[Dict[str, Any]],
    summary="Get chronological forensic timeline for a case",
    description="Returns ordered timeline milestones from email dispatch through forensic verification and correlation.",
)
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve chronological forensic timeline for a case."""
    validate_case_id(case_id)
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
        return data.get("timeline") or build_case_timeline(data, audit_events=case.audit_events)
    except Exception:
        return []


@router.get(
    "/{case_id}/correlation",
    response_model=Dict[str, Any],
    summary="Get cross-case campaign correlation for a case",
    description="Returns related investigations sharing threat indicators, relationship strength, and shared observables.",
)
def get_case_correlation(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve cross-case campaign correlation results for a case."""
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if not case.analysis_json:
        return {
            "related_case_ids": [],
            "shared_indicators": [],
            "relationship_strength": "NONE",
            "correlation_reasons": [],
            "campaign_score": 0,
        }
    try:
        data = json.loads(case.analysis_json)
        return data.get("correlation") or correlate_case(db=db, target_case=case)
    except Exception:
        return {
            "related_case_ids": [],
            "shared_indicators": [],
            "relationship_strength": "NONE",
            "correlation_reasons": [],
            "campaign_score": 0,
        }


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
    validate_case_id(case_id)
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
    validate_case_id(case_id)
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
    validate_case_id(case_id)
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
    validate_case_id(case_id)
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


@router.get(
    "/{case_id}/report",
    response_model=Dict[str, Any],
    summary="Get structured forensic report object for a case",
    description="Returns full machine-readable forensic report data including AI results, authentication, infrastructure, graph, correlation, timeline, and risk analysis.",
)
def get_case_report_data(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve full assembled forensic case report object."""
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if case.status not in (CaseStatus.ANALYZED.value, CaseStatus.REPORTED.value, CaseStatus.CORRELATED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Forensic report cannot be generated for case '{case_id}' with status '{case.status}'. Cases must be ANALYZED before report generation.",
        )
    try:
        report_data = build_case_report(db=db, case_identifier=case.case_number)
        return report_data
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assemble forensic report: {str(e)}",
        )


@router.get(
    "/{case_id}/report/json",
    summary="Download forensic case report as JSON",
    description="Generates, persists, and returns a machine-readable JSON forensic investigation report.",
)
def download_case_report_json(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Download forensic report in JSON format."""
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if case.status not in (CaseStatus.ANALYZED.value, CaseStatus.REPORTED.value, CaseStatus.CORRELATED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Forensic report cannot be generated for case '{case_id}' with status '{case.status}'. Cases must be ANALYZED before report generation.",
        )
    try:
        report_data = build_case_report(db=db, case_identifier=case.case_number)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Persist report file
    report_dir = Path("reports") / case.case_number
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "forensic_report.json"
    json_str = generate_json_report(report_data=report_data, output_path=json_path)

    # Persist report metadata in analysis_json if present
    if case.analysis_json:
        try:
            adata = json.loads(case.analysis_json)
            if "reports" not in adata:
                adata["reports"] = {}
            adata["reports"]["json_path"] = str(json_path)
            adata["reports"]["last_generated_at"] = report_data.get("generation_timestamp")
            case.analysis_json = json.dumps(adata)
            db.commit()
        except Exception:
            pass

    # Update case status to REPORTED if currently ANALYZED
    if case.status == CaseStatus.ANALYZED.value:
        update_case_status(
            db=db,
            case=case,
            status=CaseStatus.REPORTED,
            description="Forensic JSON report generated and preserved.",
        )

    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="REPORT_GENERATED",
        description=f"Forensic report exported in JSON format to {json_path}.",
    )

    filename = f"forensic_report_{case.case_number}.json"
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get(
    "/{case_id}/report/pdf",
    summary="Download forensic case report as PDF",
    description="Generates, persists, and returns a courtroom-ready PDF forensic investigation report.",
)
def download_case_report_pdf(
    case_id: str,
    db: Session = Depends(get_db),
):
    """Download forensic report in PDF format."""
    validate_case_id(case_id)
    case = get_case(db=db, case_id=case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    if case.status not in (CaseStatus.ANALYZED.value, CaseStatus.REPORTED.value, CaseStatus.CORRELATED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Forensic report cannot be generated for case '{case_id}' with status '{case.status}'. Cases must be ANALYZED before report generation.",
        )
    try:
        report_data = build_case_report(db=db, case_identifier=case.case_number)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Persist report file
    report_dir = Path("reports") / case.case_number
    report_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = report_dir / "forensic_report.pdf"
    pdf_bytes = generate_pdf_report(report_data=report_data, output_path=pdf_path)

    # Persist report metadata in analysis_json if present
    if case.analysis_json:
        try:
            adata = json.loads(case.analysis_json)
            if "reports" not in adata:
                adata["reports"] = {}
            adata["reports"]["pdf_path"] = str(pdf_path)
            adata["reports"]["last_generated_at"] = report_data.get("generation_timestamp")
            case.analysis_json = json.dumps(adata)
            db.commit()
        except Exception:
            pass

    # Update case status to REPORTED if currently ANALYZED
    if case.status == CaseStatus.ANALYZED.value:
        update_case_status(
            db=db,
            case=case,
            status=CaseStatus.REPORTED,
            description="Forensic PDF report generated and preserved.",
        )

    record_audit_event(
        db=db,
        case_id=case.id,
        event_type="REPORT_GENERATED",
        description=f"Forensic report exported in PDF format to {pdf_path}.",
    )

    filename = f"forensic_report_{case.case_number}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )

