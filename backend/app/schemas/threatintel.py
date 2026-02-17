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


# ── Identity Monitor schemas ─────────────────────────────────────────────

class MonitoredIdentityCreate(BaseModel):
    email: str
    label: str | None = None
    owner: str | None = None


class MonitoredIdentityResponse(BaseModel):
    id: str
    email: str
    label: str | None = None
    owner: str | None = None
    enabled: bool = True
    last_checked: datetime | None = None
    breach_count: int = 0
    paste_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BreachHitResponse(BaseModel):
    id: str
    identity_id: str
    email: str
    breach_name: str
    breach_title: str | None = None
    breach_domain: str | None = None
    breach_date: datetime | None = None
    added_date: datetime | None = None
    data_classes: list | None = None
    description: str | None = None
    is_verified: bool = False
    is_sensitive: bool = False
    severity: str = "medium"
    source: str = "HIBP"
    provenance: dict | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class PasswordCheckRequest(BaseModel):
    sha1_hash: str  # Client sends SHA-1 hash, never plaintext


class PasswordCheckResponse(BaseModel):
    sha1_prefix: str
    is_compromised: bool
    occurrence_count: int


class IdentitySummary(BaseModel):
    total_identities: int = 0
    total_breaches: int = 0
    critical_breaches: int = 0
    high_breaches: int = 0
    exposed_identities: int = 0
    latest_breaches: list[BreachHitResponse] = []


class BreachCheckResult(BaseModel):
    identities_checked: int = 0
    new_breaches: int = 0
    errors: list[str] = []
    duration_ms: int = 0
