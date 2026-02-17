import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class MappingSource(str, enum.Enum):
    rule = "rule"
    heuristic = "heuristic"
    manual = "manual"
    ai_suggested = "ai_suggested"


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True, index=True)
    threat_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("threats.id"), nullable=True, index=True)
    technique_id: Mapped[str] = mapped_column(String(20), index=True)
    technique_name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(20))
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
