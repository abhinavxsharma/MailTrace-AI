"""
Case management schemas and enums.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict


class CaseStatus(str, Enum):
    UPLOADED = "UPLOADED"
    PARSED = "PARSED"
    VERIFIED = "VERIFIED"
    ANALYZED = "ANALYZED"
    CORRELATED = "CORRELATED"
    REPORTED = "REPORTED"


class CaseBase(BaseModel):
    filename: Optional[str] = None
    original_filename: Optional[str] = None


class CaseCreate(CaseBase):
    pass


class CaseTestCreate(BaseModel):
    description: Optional[str] = "Synthetic test case for pipeline verification"


class CaseTestResponse(BaseModel):
    case_id: str
    status: CaseStatus

    model_config = ConfigDict(from_attributes=True)


class CaseSummaryResponse(BaseModel):
    case_id: str
    status: CaseStatus
    filename: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
