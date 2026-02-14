from pydantic import BaseModel
from datetime import datetime
from typing import Any


class FindingCreate(BaseModel):
    asset_id: str
    run_id: str | None = None
    title: str
    description: str
    severity: str = "info"
    category: str = "info"
    source_tool: str
    source_check: str
    cve_ids: list[str] = []
    cwe_id: str | None = None
    cpe: str | None = None
    evidence_artifact_ids: list[str] = []
    raw_output_snippet: str | None = None
    remediation: str | None = None
    exploitability_score: float | None = None
    exploitability_rationale: dict | None = None
    dedupe_hash: str | None = None


class FindingUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    category: str | None = None
    remediation: str | None = None
    exploitability_score: float | None = None
    status: str | None = None


class FindingResponse(BaseModel):
    id: str
    asset_id: str
    run_id: str | None = None
    title: str
    description: str
    severity: str
    category: str
    source_tool: str
    source_check: str
    cve_ids: list | None = None
    cwe_id: str | None = None
    cpe: str | None = None
    evidence_artifact_ids: list | None = None
    raw_output_snippet: str | None = None
    remediation: str | None = None
    exploitability_score: float | None = None
    exploitability_rationale: dict | None = None
    status: str
    dedupe_hash: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
