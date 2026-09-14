"""
Observed network infrastructure and geolocation schema.
Note: Forensics safety rule - observed infrastructure does not prove human identity.
"""

from typing import Optional
from pydantic import BaseModel


class InfrastructureSchema(BaseModel):
    source_ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    network_type: Optional[str] = None
    rdap_status: str = "unknown"
    dns_status: str = "unknown"
    geoip_status: str = "unknown"
