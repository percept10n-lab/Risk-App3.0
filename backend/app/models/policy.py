import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_allowlist: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    scope_denylist: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    action_allowlist: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=list)
    rate_limits: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    time_windows: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
