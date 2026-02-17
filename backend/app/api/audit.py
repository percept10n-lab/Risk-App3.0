from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.audit_event import AuditEvent
from app.models.artifact import Artifact
from app.evidence.artifact_store import ArtifactStore
from app.evidence.hash_chain import HashChain
from app.schemas.common import AuditEventResponse, ArtifactResponse, PaginatedResponse

router = APIRouter()


@router.get("/events")
async def list_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    run_id: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditEvent)
    count_query = select(sa_func.count(AuditEvent.id))
    if run_id:
        query = query.where(AuditEvent.run_id == run_id)
        count_query = count_query.where(AuditEvent.run_id == run_id)
    if entity_type:
        query = query.where(AuditEvent.entity_type == entity_type)
        count_query = count_query.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditEvent.entity_id == entity_id)
        count_query = count_query.where(AuditEvent.entity_id == entity_id)
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(
        query.order_by(AuditEvent.timestamp.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )
    events = result.scalars().all()
    return {
        "items": [AuditEventResponse.model_validate(e) for e in events],
        "total": total, "page": page, "page_size": page_size,
    }


@router.get("/trail/{run_id}")
async def get_audit_trail(
    run_id: str,
    limit: int = Query(10000, ge=1, le=50000),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(AuditEvent)
        .where(AuditEvent.run_id == run_id)
        .order_by(AuditEvent.timestamp.asc())
        .limit(limit)
    )
    result = await db.execute(query)
    events = result.scalars().all()
    return {"run_id": run_id, "events": [AuditEventResponse.model_validate(e) for e in events]}
