"""
Normalized email schema contract for forensics and AI ingestion.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class EmailSchema(BaseModel):
    from_address: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    cc_addresses: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    received_headers: List[str] = Field(default_factory=list)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachment_count: int = 0
