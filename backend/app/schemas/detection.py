"""
AI / ML threat detection schema contract.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class DetectionSignal(BaseModel):
    name: str
    contribution: str  # e.g., "+18" or "18"
    description: str


class DetectionSchema(BaseModel):
    model: str = "baseline_tfidf_lr"
    ai_threat_score: Optional[float] = None
    phishing_score: Optional[float] = None
    bec_score: Optional[float] = None
    semantic_score: Optional[float] = None
    signals: List[DetectionSignal] = Field(default_factory=list)
