"""
Cytoscape-compatible graph schemas for relationship visualization.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNodeData(BaseModel):
    id: str
    label: Optional[str] = None
    type: Optional[str] = None  # e.g., "email", "sender", "domain", "ip", "url", "infrastructure"
    value: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    data: GraphNodeData


class GraphEdgeData(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None  # e.g., "SENT_FROM", "RESOLVES_TO", "CONTAINS"
    relationship: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    data: GraphEdgeData


class GraphResponse(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
