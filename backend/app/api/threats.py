from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.threat import Threat
from app.schemas.threat import ThreatCreate, ThreatUpdate, ThreatResponse
from app.schemas.common import PaginatedResponse
from app.services.threat_service import ThreatService

router = APIRouter()


@router.get("", response_model=PaginatedResponse[ThreatResponse])
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    threat_type: str | None = None,
    zone: str | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat)
    count_query = select(sa_func.count(Threat.id))
    if asset_id:
        query = query.where(Threat.asset_id == asset_id)
        count_query = count_query.where(Threat.asset_id == asset_id)
    if threat_type:
        query = query.where(Threat.threat_type == threat_type)
        count_query = count_query.where(Threat.threat_type == threat_type)
    if zone:
        query = query.where(Threat.zone == zone)
        count_query = count_query.where(Threat.zone == zone)
    if source:
        query = query.where(Threat.source == source)
        count_query = count_query.where(Threat.source == source)
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * page_size).limit(page_size).order_by(Threat.created_at.desc()))
    return PaginatedResponse(items=result.scalars().all(), total=total, page=page, page_size=page_size)


@router.post("", response_model=ThreatResponse, status_code=201)
async def create_threat(threat_in: ThreatCreate, db: AsyncSession = Depends(get_db)):
    threat = Threat(**threat_in.model_dump())
    db.add(threat)
    await db.flush()
    await db.refresh(threat)
    return threat


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.put("/{threat_id}", response_model=ThreatResponse)
async def update_threat(threat_id: str, threat_in: ThreatUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    for field, value in threat_in.model_dump(exclude_unset=True).items():
        setattr(threat, field, value)
    threat.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(threat)
    return threat


@router.delete("/{threat_id}", status_code=204)
async def delete_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    await db.delete(threat)


class ThreatModelRequest(BaseModel):
    asset_id: str | None = None
    run_id: str | None = None


class ZoneThreatRequest(BaseModel):
    zone: str
    run_id: str | None = None


@router.post("/generate")
async def generate_threats(request: ThreatModelRequest, db: AsyncSession = Depends(get_db)):
    """Run threat modeling for one or all assets."""
    service = ThreatService(db)
    return await service.run_threat_modeling(
        asset_id=request.asset_id,
        run_id=request.run_id,
    )


@router.post("/zone-analysis")
async def zone_threat_analysis(request: ZoneThreatRequest, db: AsyncSession = Depends(get_db)):
    """Run zone-level threat analysis."""
    service = ThreatService(db)
    return await service.run_zone_threat_analysis(
        zone=request.zone,
        run_id=request.run_id,
    )
