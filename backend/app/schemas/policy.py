from pydantic import BaseModel
from datetime import datetime


class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    scope_allowlist: list[str] = []
    scope_denylist: list[str] = []
    action_allowlist: list[str] = []
    rate_limits: dict = {}
    time_windows: dict = {}
    is_default: bool = False


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    scope_allowlist: list[str] | None = None
    scope_denylist: list[str] | None = None
    action_allowlist: list[str] | None = None
    rate_limits: dict | None = None
    time_windows: dict | None = None
    is_default: bool | None = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    scope_allowlist: list | None = None
    scope_denylist: list | None = None
    action_allowlist: list | None = None
    rate_limits: dict | None = None
    time_windows: dict | None = None
    is_default: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
