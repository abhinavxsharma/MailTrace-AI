"""
Authentication and identity verification schemas.
Supports SPF, DKIM, DMARC parsing, active verification, and alignment.
"""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from app.schemas.case import CaseStatus


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class AlignmentStatus(BaseModel):
    spf: bool = False
    dkim: bool = False
    overall: bool = False


class DeclaredAuth(BaseModel):
    spf: AuthStatus = AuthStatus.UNKNOWN
    dkim: AuthStatus = AuthStatus.UNKNOWN
    dmarc: AuthStatus = AuthStatus.UNKNOWN


class VerifiedAuth(BaseModel):
    spf: AuthStatus = AuthStatus.UNKNOWN
    dkim: AuthStatus = AuthStatus.UNKNOWN
    dmarc: AuthStatus = AuthStatus.UNKNOWN


class AuthenticationSchema(BaseModel):
    spf: AuthStatus = AuthStatus.UNKNOWN
    dkim: AuthStatus = AuthStatus.UNKNOWN
    dmarc: AuthStatus = AuthStatus.UNKNOWN
    alignment: AuthStatus = AuthStatus.UNKNOWN
    spf_details: Optional[str] = None
    dkim_details: Optional[str] = None
    dmarc_details: Optional[str] = None
    declared: DeclaredAuth = Field(default_factory=DeclaredAuth)
    verified: VerifiedAuth = Field(default_factory=VerifiedAuth)
    alignment_details: AlignmentStatus = Field(default_factory=AlignmentStatus)
    raw_results: Dict[str, Any] = Field(default_factory=dict)


class IdentitySchema(BaseModel):
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    mismatch_detected: bool = False
    details: Optional[str] = None


class CaseVerifyResponse(BaseModel):
    case_id: str
    status: CaseStatus = CaseStatus.VERIFIED
    authentication: AuthenticationSchema
    identity: IdentitySchema
