from pydantic import BaseModel
from datetime import datetime
from typing import Any


class AssetCreate(BaseModel):
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    asset_type: str = "unknown"
    zone: str = "lan"
    owner: str | None = None
    criticality: str = "medium"
    data_types: list[str] = []
    update_capability: str = "unknown"
    exposure: dict = {}
    tags: list[str] = []


class AssetUpdate(BaseModel):
    ip_address: str | None = None
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    asset_type: str | None = None
    zone: str | None = None
    owner: str | None = None
    criticality: str | None = None
    data_types: list[str] | None = None
    update_capability: str | None = None
    exposure: dict | None = None
    tags: list[str] | None = None


class AssetResponse(BaseModel):
    id: str
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    asset_type: str
    zone: str
    owner: str | None = None
    criticality: str
    data_types: list | None = None
    update_capability: str
    exposure: dict | None = None
    tags: list | None = None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetOverride(BaseModel):
    field: str
    value: Any
    rationale: str
