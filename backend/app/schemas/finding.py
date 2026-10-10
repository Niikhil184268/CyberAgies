from pydantic import BaseModel
from typing import Optional


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    port: Optional[int] = None
    protocol: Optional[str] = None
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    severity: str
    description: Optional[str] = None

    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_description: Optional[str] = None
    remediation: Optional[str] = None

    class Config:
        from_attributes = True