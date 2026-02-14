import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Enum as SAEnum, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class CriticalityLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class UpdateCapability(str, enum.Enum):
    auto = "auto"
    manual = "manual"
    none = "none"
    unknown = "unknown"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), default="unknown")
    zone: Mapped[str] = mapped_column(String(50), default="lan")
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[str] = mapped_column(String(20), default=CriticalityLevel.medium.value)
    data_types: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    update_capability: Mapped[str] = mapped_column(String(20), default=UpdateCapability.unknown.value)
    exposure: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
