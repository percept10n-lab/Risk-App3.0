import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Baseline(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    zone: Mapped[str] = mapped_column(String(50), index=True)
    baseline_type: Mapped[str] = mapped_column(String(50))  # ports, services, assets, policies
    baseline_data: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    created_from_run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
