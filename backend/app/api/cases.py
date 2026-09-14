"""
Case management API endpoints.
Provides case initialization, metadata query, and status retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.case import CaseTestResponse, CaseTestCreate
from app.schemas.analysis import CaseDetailResponse
from app.services.case_service import create_case, get_case, case_to_response

router = APIRouter(prefix="/cases", tags=["Cases"])


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
