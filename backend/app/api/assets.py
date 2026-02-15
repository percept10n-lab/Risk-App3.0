import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func, delete as sa_delete

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.threat import Threat
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.models.vulnerability import Vulnerability
from app.models.override import Override
from app.models.audit_event import AuditEvent
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse, AssetOverride
from app.schemas.common import PaginatedResponse

router = APIRouter()


@router.get("/detect-gateway")
async def detect_gateway():
    """Detect the default gateway and return a suggested CIDR for discovery."""
    import asyncio
    import platform
    import re

    try:
        system = platform.system().lower()
        if system == "linux":
            proc = await asyncio.create_subprocess_exec(
                "ip", "route", "show", "default",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode().strip()
            # e.g. "default via 192.168.178.1 dev eth0"
            match = re.search(r"default via ([\d.]+)", output)
            if match:
                gateway = match.group(1)
                # Assume /24 network from gateway IP
                parts = gateway.split(".")
                cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                return {"gateway": gateway, "cidr": cidr}
        elif system == "windows":
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1 -ExpandProperty NextHop"',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            gateway = stdout.decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", gateway):
                parts = gateway.split(".")
                cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                return {"gateway": gateway, "cidr": cidr}
        # Docker / fallback — try ip route
        proc = await asyncio.create_subprocess_exec(
            "ip", "route", "show", "default",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        output = stdout.decode().strip()
        match = re.search(r"default via ([\d.]+)", output)
        if match:
            gateway = match.group(1)
            parts = gateway.split(".")
            cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return {"gateway": gateway, "cidr": cidr}
    except Exception:
        pass

    return {"gateway": None, "cidr": "192.168.1.0/24"}


@router.get("", response_model=PaginatedResponse[AssetResponse])
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    zone: str | None = None,
    asset_type: str | None = None,
    criticality: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Asset)
    count_query = select(sa_func.count(Asset.id))

    if zone:
        query = query.where(Asset.zone == zone)
        count_query = count_query.where(Asset.zone == zone)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
        count_query = count_query.where(Asset.asset_type == asset_type)
    if criticality:
        query = query.where(Asset.criticality == criticality)
        count_query = count_query.where(Asset.criticality == criticality)
    if search:
        search_filter = Asset.hostname.ilike(f"%{search}%") | Asset.ip_address.ilike(f"%{search}%")
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total = (await db.execute(count_query)).scalar() or 0
    query = query.offset((page - 1) * page_size).limit(page_size).order_by(Asset.last_seen.desc())
    result = await db.execute(query)
    items = result.scalars().all()

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(asset_in: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset = Asset(**asset_in.model_dump())
    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, asset_in: AssetUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = asset_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)
    asset.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}/delete-preview")
async def delete_preview(asset_id: str, db: AsyncSession = Depends(get_db)):
    """Preview counts of linked records that would be deleted with this asset."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    finding_ids_q = select(Finding.id).where(Finding.asset_id == asset_id)
    threat_ids_q = select(Threat.id).where(Threat.asset_id == asset_id)

    findings_count = (await db.execute(select(sa_func.count()).select_from(Finding).where(Finding.asset_id == asset_id))).scalar() or 0
    threats_count = (await db.execute(select(sa_func.count()).select_from(Threat).where(Threat.asset_id == asset_id))).scalar() or 0
    risks_count = (await db.execute(select(sa_func.count()).select_from(Risk).where(Risk.asset_id == asset_id))).scalar() or 0
    mitre_count = (await db.execute(
        select(sa_func.count()).select_from(MitreMapping).where(
            MitreMapping.finding_id.in_(finding_ids_q) | MitreMapping.threat_id.in_(threat_ids_q)
        )
    )).scalar() or 0
    vulns_count = (await db.execute(
        select(sa_func.count()).select_from(Vulnerability).where(Vulnerability.finding_id.in_(finding_ids_q))
    )).scalar() or 0

    return {
        "findings": findings_count,
        "threats": threats_count,
        "risks": risks_count,
        "mitre_mappings": mitre_count,
        "vulnerabilities": vulns_count,
    }


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    """Delete asset with cascade deletion of all linked records."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Collect IDs for cascade
    finding_ids_result = await db.execute(select(Finding.id).where(Finding.asset_id == asset_id))
    finding_ids = [r[0] for r in finding_ids_result.fetchall()]

    threat_ids_result = await db.execute(select(Threat.id).where(Threat.asset_id == asset_id))
    threat_ids = [r[0] for r in threat_ids_result.fetchall()]

    # 1. Delete MITRE mappings linked to asset's findings or threats
    mitre_deleted = 0
    if finding_ids or threat_ids:
        conditions = []
        if finding_ids:
            conditions.append(MitreMapping.finding_id.in_(finding_ids))
        if threat_ids:
            conditions.append(MitreMapping.threat_id.in_(threat_ids))
        from sqlalchemy import or_
        mitre_result = await db.execute(sa_delete(MitreMapping).where(or_(*conditions)))
        mitre_deleted = mitre_result.rowcount

    # 2. Delete vulnerabilities linked to asset's findings
    vulns_deleted = 0
    if finding_ids:
        vulns_result = await db.execute(sa_delete(Vulnerability).where(Vulnerability.finding_id.in_(finding_ids)))
        vulns_deleted = vulns_result.rowcount

    # 3. Delete risks
    risks_result = await db.execute(sa_delete(Risk).where(Risk.asset_id == asset_id))
    risks_deleted = risks_result.rowcount

    # 4. Delete findings
    findings_result = await db.execute(sa_delete(Finding).where(Finding.asset_id == asset_id))
    findings_deleted = findings_result.rowcount

    # 5. Delete threats
    threats_result = await db.execute(sa_delete(Threat).where(Threat.asset_id == asset_id))
    threats_deleted = threats_result.rowcount

    # 6. Delete asset
    await db.delete(asset)

    # Audit trail
    audit = AuditEvent(
        event_type="delete",
        entity_type="asset",
        entity_id=asset_id,
        actor="user",
        action="cascade_delete",
        old_value={
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "asset_type": asset.asset_type,
        },
        new_value={
            "findings_deleted": findings_deleted,
            "threats_deleted": threats_deleted,
            "risks_deleted": risks_deleted,
            "mitre_mappings_deleted": mitre_deleted,
            "vulnerabilities_deleted": vulns_deleted,
        },
    )
    db.add(audit)

    return {
        "status": "deleted",
        "asset_id": asset_id,
        "deleted_counts": {
            "findings": findings_deleted,
            "threats": threats_deleted,
            "risks": risks_deleted,
            "mitre_mappings": mitre_deleted,
            "vulnerabilities": vulns_deleted,
        },
    }


@router.post("/{asset_id}/override", status_code=201)
async def override_asset(asset_id: str, override_in: AssetOverride, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    original_value = getattr(asset, override_in.field, None)

    override = Override(
        entity_type="asset",
        entity_id=asset_id,
        field=override_in.field,
        original_value={"value": original_value},
        override_value={"value": override_in.value},
        rationale=override_in.rationale,
        overridden_by="user",
    )
    db.add(override)

    setattr(asset, override_in.field, override_in.value)
    asset.updated_at = datetime.utcnow()

    audit = AuditEvent(
        event_type="override",
        entity_type="asset",
        entity_id=asset_id,
        actor="user",
        action=f"override_{override_in.field}",
        old_value={"value": original_value},
        new_value={"value": override_in.value},
        rationale=override_in.rationale,
    )
    db.add(audit)

    return {"status": "overridden", "field": override_in.field}
