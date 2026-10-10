from pydantic import BaseModel


class ScanSummaryResponse(BaseModel):
    scan_id: int
    risk: str
    risk_score: int
    total_findings: int
    severity_counts: dict[str, int]