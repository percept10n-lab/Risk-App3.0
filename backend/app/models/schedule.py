import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Boolean, Integer, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "interval" | "cron"
    interval_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cron_expression: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scope: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False, default="full")  # full | discovery | vuln_only | threat_only
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
