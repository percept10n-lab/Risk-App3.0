from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.artifact import Artifact
from app.evidence.artifact_store import ArtifactStore
from app.evidence.hash_chain import HashChain
from app.schemas.common import ArtifactResponse

router = APIRouter()


@router.get("/{artifact_id}")
async def get_artifact(artifact_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return ArtifactResponse.model_validate(artifact)


@router.get("/{artifact_id}/verify")
async def verify_artifact(artifact_id: str, db: AsyncSession = Depends(get_db)):
    store = ArtifactStore(db)
    result = await store.verify(artifact_id)
    return result


@router.get("/{artifact_id}/content")
async def get_artifact_content(artifact_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact content not available")

    if artifact.content:
        return {"content": artifact.content, "content_hash": artifact.content_hash}

    store = ArtifactStore(db)
    file_path = store.storage_path / artifact.filename
    if file_path.exists():
        return {"content": file_path.read_text(encoding="utf-8"), "content_hash": artifact.content_hash}

    raise HTTPException(status_code=404, detail="Artifact content not available")


@router.get("/chain/verify")
async def verify_chain(run_id: str | None = None, db: AsyncSession = Depends(get_db)):
    chain = HashChain(db)
    result = await chain.verify_chain(run_id)
    return result
