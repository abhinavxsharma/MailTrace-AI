"""
Extracted indicator of compromise (IOC) schema contract.
"""

from typing import Optional
from pydantic import BaseModel


class IndicatorSchema(BaseModel):
    type: str  # e.g., "ip", "domain", "url", "hash", "email"
    value: str
    source: Optional[str] = None
    risk: Optional[str] = None
