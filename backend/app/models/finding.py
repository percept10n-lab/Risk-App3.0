import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, Float, Integer, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    fixed = "fixed"
    accepted = "accepted"
    exception = "exception"
    verified = "verified"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("runs.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    category: Mapped[str] = mapped_column(String(50))  # vuln, misconfig, exposure, info
    source_tool: Mapped[str] = mapped_column(String(100))
    source_check: Mapped[str] = mapped_column(String(100))
    cve_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_artifact_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    raw_output_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploitability_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    exploitability_rationale: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.open.value, index=True)
    dedupe_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
