from datetime import datetime

from pydantic import BaseModel


class ScanCreate(BaseModel):
    asset_id: int
    target: str


class ScanResponse(BaseModel):
    id: int
    asset_id: int
    target: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None

    class Config:
        from_attributes = True