from pydantic import BaseModel
from datetime import datetime


class CVEItemResponse(BaseModel):
    id: str
    cve_id: str
    product_summary: str | None = None
    cvss_base: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None
    kev_notes: str | None = None
    patch_available: bool = False
    patch_date: datetime | None = None
    vendor_project: str | None = None
    product: str | None = None
    description: str | None = None
    references: list | None = None
    provenance: dict | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AdvisoryItemResponse(BaseModel):
    id: str
    advisory_id: str
    issuer: str
    severity: str
    title: str
    summary: str | None = None
    affected_products: list | None = None
    recommendations: str | None = None
    cve_ids: list | None = None
    references: list | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    updated_at_source: datetime | None = None
    provenance: dict | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TriageItemResponse(BaseModel):
    id: str
    item_type: str
    primary_id: str
    title: str
    why_here: str
    urgency_score: int
    source_badges: list | None = None
    deep_link: str | None = None
    extra_data: dict | None = None
    updated_at: datetime

    class Config:
        from_attributes = True


class ConnectorStatusResponse(BaseModel):
    id: str
    connector_name: str
    display_name: str
    source_url: str | None = None
    last_success: datetime | None = None
    last_attempt: datetime | None = None
    last_error: str | None = None
    items_ingested: int = 0
    error_count: int = 0
    enabled: bool = True

    class Config:
        from_attributes = True


class KeyCounters(BaseModel):
    kev_additions_7d: int = 0
    exploited_wild_72h: int = 0
    high_epss_72h: int = 0
    critical_advisories_72h: int = 0
    national_advisories_72h: int = 0
    total_cves: int = 0
    total_advisories: int = 0


class ThreatIntelDashboard(BaseModel):
    triage: list[TriageItemResponse]
    counters: KeyCounters
    kev_latest: list[CVEItemResponse]
    epss_top: list[CVEItemResponse]
    advisories_latest: list[AdvisoryItemResponse]
    connectors: list[ConnectorStatusResponse]


class IngestResult(BaseModel):
    connector: str
    items_ingested: int
    errors: list[str] = []
    duration_ms: int = 0
