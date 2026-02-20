import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base
import enum


class RunStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String(20), default=RunStatus.pending.value, index=True)
    current_step: Mapped[str | None] = mapped_column(String(100), nullable=True)
    steps_completed: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    policy_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("policies.id"), nullable=True)
    scope: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(100), default="user")
    config_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    report_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
