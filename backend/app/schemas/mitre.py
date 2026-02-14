from pydantic import BaseModel
from datetime import datetime
from typing import Any


class MitreMappingCreate(BaseModel):
    finding_id: str | None = None
    threat_id: str | None = None
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = 0.5
    source: str = "manual"
    rationale: str | None = None


class MitreMappingResponse(BaseModel):
    id: str
    finding_id: str | None = None
    threat_id: str | None = None
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    source: str
    rationale: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MitreOverride(BaseModel):
    field: str
    value: Any
    rationale: str


class MitreLayerExport(BaseModel):
    name: str = "Risk Platform - ATT&CK Layer"
    versions: dict = {"attack": "14", "navigator": "4.9.1", "layer": "4.5"}
    domain: str = "enterprise-attack"
    techniques: list[dict] = []
