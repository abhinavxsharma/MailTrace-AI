"""
Authentication and identity verification schemas.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel


class AuthStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class AuthenticationSchema(BaseModel):
    spf: AuthStatus = AuthStatus.UNKNOWN
    dkim: AuthStatus = AuthStatus.UNKNOWN
    dmarc: AuthStatus = AuthStatus.UNKNOWN
    alignment: AuthStatus = AuthStatus.UNKNOWN
    spf_details: Optional[str] = None
    dkim_details: Optional[str] = None
    dmarc_details: Optional[str] = None


class IdentitySchema(BaseModel):
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    mismatch_detected: bool = False
    details: Optional[str] = None
