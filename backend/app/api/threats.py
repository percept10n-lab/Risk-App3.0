from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.threat import Threat
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.mitre_mapping import MitreMapping
from app.schemas.threat import ThreatCreate, ThreatUpdate, ThreatResponse
from app.schemas.common import PaginatedResponse
from app.services.threat_service import ThreatService
from app.services.pagination import paginate

router = APIRouter()


@router.get("")
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    threat_type: str | None = None,
    zone: str | None = None,
    source: str | None = None,
    include_asset: bool = False,
    include_findings: bool = False,
    include_mitre: bool = False,
    db: AsyncSession = Depends(get_db),
):
    query = select(Threat)
    if asset_id:
        query = query.where(Threat.asset_id == asset_id)
    if threat_type:
        query = query.where(Threat.threat_type == threat_type)
    if zone:
        query = query.where(Threat.zone == zone)
    if source:
        query = query.where(Threat.source == source)
    query = query.order_by(Threat.created_at.desc())

    items, total = await paginate(db, query, page, page_size)

    serialized = [ThreatResponse.model_validate(t).model_dump() for t in items]

    if not include_asset and not include_findings and not include_mitre:
        return {"items": serialized, "total": total, "page": page, "page_size": page_size}

    # Enrich with asset data
    asset_cache: dict[str, dict | None] = {}
    if include_asset:
        asset_ids = list({t.asset_id for t in items if t.asset_id})
        if asset_ids:
            asset_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
            for a in asset_result.scalars().all():
                asset_cache[a.id] = {"id": a.id, "hostname": a.hostname, "ip_address": a.ip_address}

    # Enrich with linked findings
    finding_cache: dict[str, list] = {}
    if include_findings:
        all_finding_ids: list[str] = []
        for t in items:
            fids = t.linked_finding_ids or []
            all_finding_ids.extend(fids)
        unique_finding_ids = list(set(all_finding_ids))
        finding_map: dict[str, dict] = {}
        if unique_finding_ids:
            finding_result = await db.execute(select(Finding).where(Finding.id.in_(unique_finding_ids)))
            for f in finding_result.scalars().all():
                finding_map[f.id] = {"id": f.id, "title": f.title, "severity": f.severity}
        for t in items:
            fids = t.linked_finding_ids or []
            finding_cache[t.id] = [finding_map[fid] for fid in fids if fid in finding_map]

    # Enrich with MITRE techniques
    mitre_cache: dict[str, list] = {}
    if include_mitre:
        threat_ids = [t.id for t in items]
        if threat_ids:
            mitre_result = await db.execute(
                select(MitreMapping).where(MitreMapping.threat_id.in_(threat_ids))
            )
            for m in mitre_result.scalars().all():
                mitre_cache.setdefault(m.threat_id, []).append({
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                })

    for item_dict in serialized:
        if include_asset:
            item_dict["asset"] = asset_cache.get(item_dict.get("asset_id") or "")
        if include_findings:
            item_dict["linked_findings"] = finding_cache.get(item_dict["id"], [])
        if include_mitre:
            item_dict["mitre_techniques"] = mitre_cache.get(item_dict["id"], [])

    return {"items": serialized, "total": total, "page": page, "page_size": page_size}


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
