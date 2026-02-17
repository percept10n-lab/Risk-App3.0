import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, Float, Boolean, Integer, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class CVEItem(Base):
    """Canonical CVE with provenance tracking."""
    __tablename__ = "cve_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # CVE-YYYY-NNNN
    product_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cvss_base: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    vendor_project: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    provenance: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())


class AdvisoryItem(Base):
    """National/vendor advisory with provenance."""
    __tablename__ = "advisory_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    advisory_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    issuer: Mapped[str] = mapped_column(String(50), index=True)  # BSI, CERT-Bund, ENISA, Vendor
    severity: Mapped[str] = mapped_column(String(20), index=True)  # info, low, medium, high, critical
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_products: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    references: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at_source: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    provenance: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())


class TriageItem(Base):
    """Landing page triage item — computed from CVEs + advisories."""
    __tablename__ = "triage_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    item_type: Mapped[str] = mapped_column(String(50), index=True)  # exploited_cve, high_risk_cve, advisory, campaign
    primary_id: Mapped[str] = mapped_column(String(100), index=True)  # CVE-ID or advisory ID
    title: Mapped[str] = mapped_column(String(500))
    why_here: Mapped[str] = mapped_column(String(500))
    urgency_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    source_badges: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    deep_link: Mapped[str | None] = mapped_column(String(500), nullable=True)
    extra_data: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())


class ConnectorStatus(Base):
    """Per-source connector health tracking."""
    __tablename__ = "connector_status"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    connector_name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    items_ingested: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
