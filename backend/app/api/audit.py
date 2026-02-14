from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.audit_event import AuditEvent
from app.models.artifact import Artifact
from app.evidence.artifact_store import ArtifactStore
from app.evidence.hash_chain import HashChain
from app.schemas.common import AuditEventResponse, ArtifactResponse

router = APIRouter()


@router.get("/events")
async def list_audit_events(
    run_id: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit)
    if run_id:
        query = query.where(AuditEvent.run_id == run_id)
    if entity_type:
        query = query.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditEvent.entity_id == entity_id)
    result = await db.execute(query)
    events = result.scalars().all()
    return {"events": [AuditEventResponse.model_validate(e) for e in events]}


@router.get("/trail/{run_id}")
async def get_audit_trail(run_id: str, db: AsyncSession = Depends(get_db)):
    query = select(AuditEvent).where(AuditEvent.run_id == run_id).order_by(AuditEvent.timestamp.asc())
    result = await db.execute(query)
    events = result.scalars().all()
    return {"run_id": run_id, "events": [AuditEventResponse.model_validate(e) for e in events]}
