import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Override(Base):
    __tablename__ = "overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    entity_type: Mapped[str] = mapped_column(String(50), index=True)
    entity_id: Mapped[str] = mapped_column(String(36), index=True)
    field: Mapped[str] = mapped_column(String(100))
    original_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    override_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rationale: Mapped[str] = mapped_column(Text)
    overridden_by: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=func.now())
