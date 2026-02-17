from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.models.override import Override
from app.models.audit_event import AuditEvent
from app.schemas.finding import FindingCreate, FindingUpdate, FindingResponse
from app.schemas.common import PaginatedResponse, OverrideRequest
from app.services.vuln_scan_service import VulnScanService
from app.services.pagination import paginate

router = APIRouter()


@router.get("")
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    include_asset: bool = False,
    include_mitre: bool = False,
    db: AsyncSession = Depends(get_db),
):
    query = select(Finding)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    query = query.order_by(Finding.created_at.desc())

    items, total = await paginate(db, query, page, page_size)

    # Always serialize to dicts for consistent response
    serialized = [FindingResponse.model_validate(f).model_dump() for f in items]

    if not include_asset and not include_mitre:
        return {"items": serialized, "total": total, "page": page, "page_size": page_size}

    # Enrich with asset and/or MITRE data
    asset_cache: dict[str, dict | None] = {}
    if include_asset:
        asset_ids = list({f.asset_id for f in items if f.asset_id})
        if asset_ids:
            asset_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
            for a in asset_result.scalars().all():
                asset_cache[a.id] = {"id": a.id, "hostname": a.hostname, "ip_address": a.ip_address}

    mitre_cache: dict[str, list] = {}
    if include_mitre:
        finding_ids = [f.id for f in items]
        if finding_ids:
            mitre_result = await db.execute(
                select(MitreMapping).where(MitreMapping.finding_id.in_(finding_ids))
            )
            for m in mitre_result.scalars().all():
                mitre_cache.setdefault(m.finding_id, []).append({
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                })

    for item_dict in serialized:
        if include_asset:
            item_dict["asset"] = asset_cache.get(item_dict["asset_id"])
        if include_mitre:
            item_dict["mitre_techniques"] = mitre_cache.get(item_dict["id"], [])

    return {"items": serialized, "total": total, "page": page, "page_size": page_size}


@router.post("", response_model=FindingResponse, status_code=201)
async def create_finding(finding_in: FindingCreate, db: AsyncSession = Depends(get_db)):
    finding = Finding(**finding_in.model_dump())
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/{finding_id}/context")
async def get_finding_context(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get a finding with full context: asset, MITRE mappings, risk scenarios."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Asset
    asset_data = None
    if finding.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == finding.asset_id))
        asset = asset_result.scalar_one_or_none()
        if asset:
            asset_data = {
                "id": asset.id, "hostname": asset.hostname, "ip_address": asset.ip_address,
                "asset_type": asset.asset_type, "zone": asset.zone, "criticality": asset.criticality,
                "vendor": asset.vendor, "os_guess": asset.os_guess,
            }

    # MITRE mappings
    mitre_result = await db.execute(
        select(MitreMapping).where(MitreMapping.finding_id == finding_id)
    )
    mitre_mappings = [
        {
            "id": m.id, "technique_id": m.technique_id, "technique_name": m.technique_name,
            "tactic": m.tactic, "confidence": m.confidence, "source": m.source,
        }
        for m in mitre_result.scalars().all()
    ]

    # Risk scenarios
    risk_result = await db.execute(
        select(Risk).where(Risk.finding_id == finding_id)
    )
    risks = [
        {
            "id": r.id, "scenario": r.scenario, "risk_level": r.risk_level,
            "likelihood": r.likelihood, "impact": r.impact,
        }
        for r in risk_result.scalars().all()
    ]

    finding_data = FindingResponse.model_validate(finding).model_dump()

    return {
        "finding": finding_data,
        "asset": asset_data,
        "mitre_mappings": mitre_mappings,
        "risks": risks,
    }


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: str, finding_in: FindingUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = finding_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)
    finding.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/override", status_code=201)
async def override_finding(finding_id: str, override_in: OverrideRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    original_value = getattr(finding, override_in.field, None)

    override = Override(
        entity_type="finding", entity_id=finding_id, field=override_in.field,
        original_value={"value": original_value}, override_value={"value": override_in.value},
        rationale=override_in.rationale, overridden_by="user",
    )
    db.add(override)
    setattr(finding, override_in.field, override_in.value)

    audit = AuditEvent(
        event_type="override", entity_type="finding", entity_id=finding_id,
        actor="user", action=f"override_{override_in.field}",
        old_value={"value": original_value}, new_value={"value": override_in.value},
        rationale=override_in.rationale,
    )
    db.add(audit)

    return {"status": "overridden", "field": override_in.field}


class VulnScanRequest(BaseModel):
    asset_id: str | None = None
    run_id: str | None = None
    timeout: int = 300


@router.post("/scan")
async def run_vuln_scan(request: VulnScanRequest, db: AsyncSession = Depends(get_db)):
    """Run vulnerability scanning on one or all assets."""
    service = VulnScanService(db)
    return await service.run_vuln_scan(
        asset_id=request.asset_id,
        run_id=request.run_id,
        timeout=request.timeout,
    )
