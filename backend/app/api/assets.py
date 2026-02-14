import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.asset import Asset
from app.models.override import Override
from app.models.audit_event import AuditEvent
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse, AssetOverride
from app.schemas.common import PaginatedResponse

router = APIRouter()


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


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)


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
