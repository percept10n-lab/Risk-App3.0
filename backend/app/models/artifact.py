import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, JSON, Text, Integer, LargeBinary, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("runs.id"), nullable=True)
    artifact_type: Mapped[str] = mapped_column(String(50))  # raw_output, log, config, screenshot
    filename: Mapped[str] = mapped_column(String(500))
    content_hash: Mapped[str] = mapped_column(String(64))  # SHA-256
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100))
    tool_version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target: Mapped[str] = mapped_column(String(255))
    parameters: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
