import hashlib
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.artifact import Artifact
from app.config import settings


class ArtifactStore:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.storage_path = Path(settings.artifacts_dir)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_hash(content: str | bytes) -> str:
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    async def get_last_hash(self, run_id: str | None = None) -> str | None:
        query = select(Artifact).order_by(Artifact.timestamp.desc()).limit(1)
        if run_id:
            query = query.where(Artifact.run_id == run_id)
        result = await self.db.execute(query)
        last = result.scalar_one_or_none()
        return last.content_hash if last else None

    async def store(
        self,
        content: str,
        artifact_type: str,
        tool_name: str,
        target: str,
        run_id: str | None = None,
        command: str | None = None,
        exit_code: int | None = None,
        parameters: dict | None = None,
        tool_version: str = "1.0.0",
    ) -> Artifact:
        content_hash = self.compute_hash(content)
        prev_hash = await self.get_last_hash(run_id)

        artifact_id = str(uuid.uuid4())
        filename = f"{artifact_id}_{tool_name}_{artifact_type}.txt"

        file_path = self.storage_path / filename
        file_path.write_text(content, encoding="utf-8")

        artifact = Artifact(
            id=artifact_id,
            run_id=run_id,
            artifact_type=artifact_type,
            filename=filename,
            content_hash=content_hash,
            content=content if len(content) < 50000 else None,
            tool_name=tool_name,
            tool_version=tool_version,
            command=command,
            exit_code=exit_code,
            target=target,
            parameters=parameters or {},
            timestamp=datetime.utcnow(),
            prev_hash=prev_hash,
        )
        self.db.add(artifact)
        await self.db.flush()
        return artifact

    async def retrieve(self, artifact_id: str) -> Artifact | None:
        result = await self.db.execute(
            select(Artifact).where(Artifact.id == artifact_id)
        )
        return result.scalar_one_or_none()

    async def verify(self, artifact_id: str) -> dict:
        artifact = await self.retrieve(artifact_id)
        if not artifact:
            return {"valid": False, "error": "Artifact not found"}

        file_path = self.storage_path / artifact.filename
        if file_path.exists():
            stored_content = file_path.read_text(encoding="utf-8")
            actual_hash = self.compute_hash(stored_content)
        elif artifact.content:
            actual_hash = self.compute_hash(artifact.content)
        else:
            return {"valid": False, "error": "Content not available"}

        return {
            "valid": actual_hash == artifact.content_hash,
            "expected_hash": artifact.content_hash,
            "actual_hash": actual_hash,
            "artifact_id": artifact_id,
        }
