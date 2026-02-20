import uuid
from datetime import datetime, date
from sqlalchemy import String, DateTime, Date, JSON, Text, ForeignKey, Index, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class LikelihoodLevel(str, enum.Enum):
    very_low = "very_low"
    low = "low"
    medium = "medium"
    high = "high"
    very_high = "very_high"


class ImpactLevel(str, enum.Enum):
    negligible = "negligible"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TreatmentOption(str, enum.Enum):
    mitigate = "mitigate"
    transfer = "transfer"
    avoid = "avoid"
    accept = "accept"


class CIAImpact(str, enum.Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


class RiskStatus(str, enum.Enum):
    identified = "identified"
    analyzed = "analyzed"
    evaluated = "evaluated"
    treated = "treated"
    monitoring = "monitoring"


class Risk(Base):
    __tablename__ = "risks"
    __table_args__ = (
        Index("idx_risk_asset_level", "asset_id", "risk_level"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    threat_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("threats.id"), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True, index=True)
    scenario: Mapped[str] = mapped_column(Text)
    likelihood: Mapped[str] = mapped_column(String(20))
    likelihood_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str] = mapped_column(String(20))
    impact_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    confidentiality_impact: Mapped[str] = mapped_column(String(10), default=CIAImpact.none.value)
    integrity_impact: Mapped[str] = mapped_column(String(10), default=CIAImpact.none.value)
    availability_impact: Mapped[str] = mapped_column(String(10), default=CIAImpact.none.value)
    treatment: Mapped[str | None] = mapped_column(String(20), nullable=True)
    treatment_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    treatment_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    treatment_due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    residual_risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    residual_likelihood: Mapped[str | None] = mapped_column(String(20), nullable=True)
    residual_impact: Mapped[str | None] = mapped_column(String(20), nullable=True)
    treatment_measures: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    likelihood_factors: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    impact_factors: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=RiskStatus.identified.value, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
