from pydantic import BaseModel
from typing import Any, Generic, TypeVar
from datetime import datetime

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    page_size: int = 50


class OverrideRequest(BaseModel):
    field: str
    value: Any
    rationale: str


class AuditEventResponse(BaseModel):
    id: str
    run_id: str | None = None
    event_type: str
    entity_type: str
    entity_id: str
    actor: str
    action: str
    old_value: dict | None = None
    new_value: dict | None = None
    rationale: str | None = None
    timestamp: datetime

    class Config:
        from_attributes = True


class ArtifactResponse(BaseModel):
    id: str
    run_id: str | None = None
    artifact_type: str
    filename: str
    content_hash: str
    tool_name: str
    tool_version: str
    command: str | None = None
    exit_code: int | None = None
    target: str
    parameters: dict | None = None
    timestamp: datetime
    prev_hash: str | None = None

    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    detail: str
    error_code: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
