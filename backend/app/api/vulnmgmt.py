from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.audit_event import AuditEvent
from app.services.vuln_mgmt_service import VulnMgmtService
from app.schemas.common import PaginatedResponse

router = APIRouter()


class StatusUpdateRequest(BaseModel):
    status: str
    comment: str | None = None
    assigned_to: str | None = None


@router.get("")
async def list_vulns(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Vulnerability)
    count_query = select(sa_func.count(Vulnerability.id))
    if status:
        query = query.where(Vulnerability.status == status)
        count_query = count_query.where(Vulnerability.status == status)
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(
        query.offset((page - 1) * page_size).limit(page_size).order_by(Vulnerability.created_at.desc())
    )
    items = result.scalars().all()
    return {
        "items": [
            {
                "id": v.id,
                "finding_id": v.finding_id,
                "status": v.status,
                "sla_deadline": str(v.sla_deadline) if v.sla_deadline else None,
                "assigned_to": v.assigned_to,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "updated_at": v.updated_at.isoformat() if v.updated_at else None,
            }
            for v in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/metrics")
async def get_metrics(db: AsyncSession = Depends(get_db)):
    """Get vulnerability management metrics."""
    service = VulnMgmtService(db)
    return await service.get_metrics()


@router.post("/create-from-findings")
async def create_from_findings(run_id: str | None = None, db: AsyncSession = Depends(get_db)):
    """Create vulnerability tracking items from open findings."""
    service = VulnMgmtService(db)
    return await service.create_from_findings(run_id=run_id)


@router.get("/finding/{finding_id}/enriched")
async def get_enriched_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get finding with full context for vulnerability management."""
    service = VulnMgmtService(db)
    result = await service.get_enriched_finding(finding_id)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.get("/{vuln_id}")
async def get_vuln(vuln_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {
        "id": vuln.id,
        "finding_id": vuln.finding_id,
        "status": vuln.status,
        "sla_deadline": str(vuln.sla_deadline) if vuln.sla_deadline else None,
        "assigned_to": vuln.assigned_to,
        "comments": vuln.comments,
        "history": vuln.history,
        "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
        "updated_at": vuln.updated_at.isoformat() if vuln.updated_at else None,
    }


@router.put("/{vuln_id}")
async def update_vuln(vuln_id: str, request: StatusUpdateRequest, db: AsyncSession = Depends(get_db)):
    service = VulnMgmtService(db)
    result = await service.update_status(
        vuln_id=vuln_id,
        new_status=request.status,
        comment=request.comment,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])

    # Update assignment if provided
    if request.assigned_to is not None:
        vuln_result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
        vuln = vuln_result.scalar_one_or_none()
        if vuln:
            vuln.assigned_to = request.assigned_to

    return result


@router.post("/{vuln_id}/rescan")
async def rescan_vuln(vuln_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"status": "rescan_queued", "vuln_id": vuln_id}
