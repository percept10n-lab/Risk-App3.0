from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.finding import Finding
from app.services.nmap_service import NmapService, SCAN_PROFILES

router = APIRouter()


class ScanRequest(BaseModel):
    asset_id: str | None = None
    target: str | None = None
    profile_id: str
    run_id: str | None = None
    params: dict | None = None


class VerifyRequest(BaseModel):
    asset_id: str
    finding_ids: list[str] | None = None
    run_id: str | None = None


class AssessRiskRequest(BaseModel):
    asset_id: str
    finding_ids: list[str] | None = None
    run_id: str | None = None


@router.get("/profiles")
async def list_profiles():
    """List available nmap scan profiles grouped by category."""
    grouped: dict[str, list] = {"active": [], "passive": [], "offensive": []}
    for pid, profile in SCAN_PROFILES.items():
        cat = profile["category"]
        grouped.setdefault(cat, []).append({
            "id": pid,
            **profile,
        })
    return {"profiles": grouped}


@router.post("/scan")
async def run_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """Execute an nmap scan against an asset or a free target IP."""
    if not request.asset_id and not request.target:
        return {"status": "error", "error": "Either asset_id or target IP must be provided"}
    service = NmapService(db)
    return await service.execute_scan(
        asset_id=request.asset_id,
        target=request.target,
        profile_id=request.profile_id,
        run_id=request.run_id,
        params=request.params,
    )


@router.get("/results")
async def get_results(
    asset_id: str | None = None,
    profile_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get nmap scan findings."""
    from sqlalchemy import func as sa_func

    query = select(Finding).where(Finding.source_tool.like("nmap_%"))
    count_query = select(sa_func.count(Finding.id)).where(Finding.source_tool.like("nmap_%"))

    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
        count_query = count_query.where(Finding.asset_id == asset_id)
    if profile_id:
        query = query.where(Finding.source_tool == f"nmap_{profile_id}")
        count_query = count_query.where(Finding.source_tool == f"nmap_{profile_id}")

    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(
        query.offset((page - 1) * page_size).limit(page_size).order_by(Finding.created_at.desc())
    )
    items = list(result.scalars().all())

    from app.schemas.finding import FindingResponse
    serialized = [FindingResponse.model_validate(f).model_dump() for f in items]

    return {"items": serialized, "total": total, "page": page, "page_size": page_size}


@router.post("/verify")
async def verify_findings(request: VerifyRequest, db: AsyncSession = Depends(get_db)):
    """Verify nmap findings with targeted vulnerability checks."""
    service = NmapService(db)
    return await service.verify_with_vuln_scan(
        asset_id=request.asset_id,
        finding_ids=request.finding_ids,
        run_id=request.run_id,
    )


@router.post("/assess-risk")
async def assess_risk(request: AssessRiskRequest, db: AsyncSession = Depends(get_db)):
    """Assess risk for nmap scan findings."""
    service = NmapService(db)
    return await service.assess_risk(
        asset_id=request.asset_id,
        finding_ids=request.finding_ids,
        run_id=request.run_id,
    )
