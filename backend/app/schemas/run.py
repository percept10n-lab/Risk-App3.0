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
