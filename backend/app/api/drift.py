from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.drift_service import DriftService

router = APIRouter()


class BaselineCreateRequest(BaseModel):
    zone: str = "lan"
    baseline_type: str = "full"
    run_id: str | None = None


@router.get("/changes")
async def list_changes(zone: str | None = None, db: AsyncSession = Depends(get_db)):
    """Detect changes since the last baseline."""
    service = DriftService(db)
    return await service.detect_changes(zone=zone)


@router.post("/baseline")
async def create_baseline(
    body: BaselineCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a baseline snapshot for a network zone."""
    service = DriftService(db)
    return await service.create_baseline(
        zone=body.zone,
        baseline_type=body.baseline_type,
        run_id=body.run_id,
    )


@router.get("/alerts")
async def list_alerts(zone: str | None = None, db: AsyncSession = Depends(get_db)):
    """Get high/critical drift alerts."""
    service = DriftService(db)
    return await service.get_alerts(zone=zone)


@router.get("/baselines")
async def list_baselines(zone: str | None = None, db: AsyncSession = Depends(get_db)):
    """Get baseline history."""
    service = DriftService(db)
    return await service.get_baseline_history(zone=zone)
