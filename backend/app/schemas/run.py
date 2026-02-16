from pydantic import BaseModel
from datetime import datetime


class RunCreate(BaseModel):
    policy_id: str | None = None
    scope: dict = {}
    triggered_by: str = "user"
    config_snapshot: dict = {}


class RunResponse(BaseModel):
    id: str
    status: str
    current_step: str | None = None
    steps_completed: list | None = None
    policy_id: str | None = None
    scope: dict | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    triggered_by: str
    config_snapshot: dict | None = None
    created_at: datetime

    class Config:
        from_attributes = True


# --- Workflow Completion Report schemas ---

class StepDetail(BaseModel):
    step: str
    label: str
    status: str  # completed | failed | skipped
    items_count: int = 0
    details: list[dict] = []


class ReportSummary(BaseModel):
    total_assets: int = 0
    total_findings: int = 0
    total_threats: int = 0
    total_risks: int = 0
    total_mitre_mappings: int = 0
    total_baselines: int = 0
    findings_by_severity: dict[str, int] = {}
    risks_by_level: dict[str, int] = {}


class WorkflowReport(BaseModel):
    run_id: str
    status: str
    scope: dict | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    triggered_by: str
    steps: list[StepDetail] = []
    summary: ReportSummary = ReportSummary()
