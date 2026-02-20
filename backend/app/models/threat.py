import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class ThreatSource(str, enum.Enum):
    rule = "rule"
    manual = "manual"
    ai_suggested = "ai_suggested"


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    threat_type: Mapped[str] = mapped_column(String(50))  # STRIDE category or custom
    source: Mapped[str] = mapped_column(String(20))
    zone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    trust_boundary: Mapped[str | None] = mapped_column(String(100), nullable=True)
    linked_finding_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    c4_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    stride_category_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
