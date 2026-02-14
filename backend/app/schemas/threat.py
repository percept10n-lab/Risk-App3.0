from pydantic import BaseModel
from datetime import datetime


class ThreatCreate(BaseModel):
    asset_id: str | None = None
    title: str
    description: str
    threat_type: str
    source: str = "manual"
    zone: str | None = None
    trust_boundary: str | None = None
    linked_finding_ids: list[str] = []
    confidence: float = 0.5
    rationale: str | None = None


class ThreatUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    threat_type: str | None = None
    zone: str | None = None
    trust_boundary: str | None = None
    linked_finding_ids: list[str] | None = None
    confidence: float | None = None
    rationale: str | None = None


class ThreatResponse(BaseModel):
    id: str
    asset_id: str | None = None
    title: str
    description: str
    threat_type: str
    source: str
    zone: str | None = None
    trust_boundary: str | None = None
    linked_finding_ids: list | None = None
    confidence: float
    rationale: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
