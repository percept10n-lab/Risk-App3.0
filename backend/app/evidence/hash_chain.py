import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.artifact import Artifact


class HashChain:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def compute_chain_hash(content_hash: str, prev_hash: str | None) -> str:
        chain_input = f"{prev_hash or 'GENESIS'}:{content_hash}"
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    async def verify_chain(self, run_id: str | None = None) -> dict:
        query = select(Artifact).order_by(Artifact.timestamp.asc())
        if run_id:
            query = query.where(Artifact.run_id == run_id)

        result = await self.db.execute(query)
        artifacts = result.scalars().all()

        if not artifacts:
            return {"valid": True, "length": 0, "message": "Empty chain"}

        broken_links = []
        prev_hash = None

        for i, artifact in enumerate(artifacts):
            if artifact.prev_hash != prev_hash:
                broken_links.append({
                    "index": i,
                    "artifact_id": artifact.id,
                    "expected_prev": prev_hash,
                    "actual_prev": artifact.prev_hash,
                })
            prev_hash = artifact.content_hash

        return {
            "valid": len(broken_links) == 0,
            "length": len(artifacts),
            "broken_links": broken_links,
            "first_artifact": artifacts[0].id if artifacts else None,
            "last_artifact": artifacts[-1].id if artifacts else None,
        }
