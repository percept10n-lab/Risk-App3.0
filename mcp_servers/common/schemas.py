from pydantic import BaseModel
from typing import Any
from datetime import datetime


class ToolResult(BaseModel):
    success: bool
    data: Any = None
    error: str | None = None
    artifacts: list[dict] = []
    metadata: dict = {}


class ScanTarget(BaseModel):
    ip: str
    port: int | None = None
    protocol: str = "tcp"
    hostname: str | None = None


class FindingResult(BaseModel):
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    category: str  # vuln, misconfig, exposure, info
    source_tool: str
    source_check: str
    cve_ids: list[str] = []
    cwe_id: str | None = None
    evidence: str = ""
    remediation: str | None = None
    raw_output: str = ""


class AssetResult(BaseModel):
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    open_ports: list[int] = []
    services: list[dict] = []
