from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.mitre_mapping import MitreMapping
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.threat import Threat
from app.models.override import Override
from app.models.audit_event import AuditEvent
from app.schemas.mitre import MitreMappingCreate, MitreMappingResponse, MitreOverride, MitreLayerExport
from app.schemas.common import PaginatedResponse
from app.services.mitre_service import MitreService

router = APIRouter()


@router.get("/mappings", response_model=PaginatedResponse[MitreMappingResponse])
async def list_mappings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    technique_id: str | None = None,
    tactic: str | None = None,
    finding_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(MitreMapping)
    count_query = select(sa_func.count(MitreMapping.id))
    if technique_id:
        query = query.where(MitreMapping.technique_id == technique_id)
        count_query = count_query.where(MitreMapping.technique_id == technique_id)
    if tactic:
        query = query.where(MitreMapping.tactic == tactic)
        count_query = count_query.where(MitreMapping.tactic == tactic)
    if finding_id:
        query = query.where(MitreMapping.finding_id == finding_id)
        count_query = count_query.where(MitreMapping.finding_id == finding_id)
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * page_size).limit(page_size))
    return PaginatedResponse(items=result.scalars().all(), total=total, page=page, page_size=page_size)


@router.get("/mappings/enriched")
async def list_enriched_mappings(
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Return mappings enriched with finding, asset, and threat info plus exploitability flag."""
    count_query = select(sa_func.count(MitreMapping.id))
    total = (await db.execute(count_query)).scalar() or 0

    result = await db.execute(
        select(MitreMapping).offset((page - 1) * page_size).limit(page_size)
    )
    mappings = list(result.scalars().all())

    if not mappings:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    # Batch fetch findings
    finding_ids = list({m.finding_id for m in mappings if m.finding_id})
    finding_cache: dict[str, Finding] = {}
    if finding_ids:
        f_result = await db.execute(select(Finding).where(Finding.id.in_(finding_ids)))
        for f in f_result.scalars().all():
            finding_cache[f.id] = f

    # Batch fetch assets from findings
    asset_ids = list({f.asset_id for f in finding_cache.values() if f.asset_id})
    asset_cache: dict[str, Asset] = {}
    if asset_ids:
        a_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
        for a in a_result.scalars().all():
            asset_cache[a.id] = a

    # Batch fetch threats
    threat_ids = list({m.threat_id for m in mappings if m.threat_id})
    threat_cache: dict[str, Threat] = {}
    if threat_ids:
        t_result = await db.execute(select(Threat).where(Threat.id.in_(threat_ids)))
        for t in t_result.scalars().all():
            threat_cache[t.id] = t

    enriched = []
    for m in mappings:
        finding = finding_cache.get(m.finding_id) if m.finding_id else None
        asset = asset_cache.get(finding.asset_id) if finding and finding.asset_id else None
        threat = threat_cache.get(m.threat_id) if m.threat_id else None

        is_exploitable = bool(
            finding and finding.status == "open" and finding.severity in ("high", "critical")
        )

        enriched.append({
            "id": m.id,
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic": m.tactic,
            "confidence": m.confidence,
            "source": m.source,
            "finding_id": m.finding_id,
            "finding_title": finding.title if finding else None,
            "finding_severity": finding.severity if finding else None,
            "finding_status": finding.status if finding else None,
            "asset_id": finding.asset_id if finding else None,
            "asset_hostname": asset.hostname if asset else None,
            "asset_ip": asset.ip_address if asset else None,
            "threat_id": m.threat_id,
            "threat_title": threat.title if threat else None,
            "is_exploitable": is_exploitable,
        })

    return {"items": enriched, "total": total, "page": page, "page_size": page_size}


@router.post("/mappings", response_model=MitreMappingResponse, status_code=201)
async def create_mapping(mapping_in: MitreMappingCreate, db: AsyncSession = Depends(get_db)):
    mapping = MitreMapping(**mapping_in.model_dump())
    db.add(mapping)
    await db.flush()
    await db.refresh(mapping)
    return mapping


@router.get("/layer-export")
async def export_layer(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MitreMapping))
    mappings = result.scalars().all()

    techniques = []
    technique_map: dict[str, dict] = {}
    for m in mappings:
        if m.technique_id not in technique_map:
            technique_map[m.technique_id] = {
                "techniqueID": m.technique_id,
                "tactic": m.tactic,
                "score": 0,
                "color": "",
                "comment": "",
                "enabled": True,
                "metadata": [],
            }
        technique_map[m.technique_id]["score"] = max(
            technique_map[m.technique_id]["score"],
            int(m.confidence * 100),
        )

    techniques = list(technique_map.values())
    return MitreLayerExport(techniques=techniques).model_dump()


@router.post("/mappings/{mapping_id}/override", status_code=201)
async def override_mapping(mapping_id: str, override_in: MitreOverride, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MitreMapping).where(MitreMapping.id == mapping_id))
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    original_value = getattr(mapping, override_in.field, None)
    override = Override(
        entity_type="mitre_mapping", entity_id=mapping_id, field=override_in.field,
        original_value={"value": original_value}, override_value={"value": override_in.value},
        rationale=override_in.rationale, overridden_by="user",
    )
    db.add(override)
    setattr(mapping, override_in.field, override_in.value)
    return {"status": "overridden", "field": override_in.field}


class MitreGenerateRequest(BaseModel):
    run_id: str | None = None


@router.post("/generate")
async def generate_mappings(request: MitreGenerateRequest, db: AsyncSession = Depends(get_db)):
    """Auto-generate MITRE ATT&CK mappings from all findings and threats."""
    service = MitreService(db)
    return await service.run_mapping(run_id=request.run_id)


@router.get("/navigator-export")
async def export_navigator(db: AsyncSession = Depends(get_db)):
    """Export mappings as a valid ATT&CK Navigator layer JSON."""
    service = MitreService(db)
    return await service.export_navigator_layer()
