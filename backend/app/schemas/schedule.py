from pydantic import BaseModel
from datetime import datetime


class ScanScheduleCreate(BaseModel):
    name: str
    schedule_type: str  # "interval" | "cron"
    interval_hours: int | None = None
    cron_expression: str | None = None
    scope: dict | None = None
    scan_type: str = "full"
    enabled: bool = True


class ScanScheduleUpdate(BaseModel):
    name: str | None = None
    schedule_type: str | None = None
    interval_hours: int | None = None
    cron_expression: str | None = None
    scope: dict | None = None
    scan_type: str | None = None
    enabled: bool | None = None


class ScanScheduleResponse(BaseModel):
    id: str
    name: str
    schedule_type: str
    interval_hours: int | None = None
    cron_expression: str | None = None
    scope: dict | None = None
    scan_type: str
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    last_run_id: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
