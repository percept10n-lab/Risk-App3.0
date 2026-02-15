from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.schedule import ScanSchedule
from app.schemas.schedule import ScanScheduleCreate, ScanScheduleUpdate, ScanScheduleResponse

router = APIRouter()


@router.get("", response_model=list[ScanScheduleResponse])
async def list_schedules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanSchedule).order_by(ScanSchedule.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=ScanScheduleResponse, status_code=201)
async def create_schedule(
    schedule_in: ScanScheduleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    schedule = ScanSchedule(**schedule_in.model_dump())
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)

    # Add to scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler:
        await scheduler.add_schedule(schedule)

    return schedule


@router.get("/{schedule_id}", response_model=ScanScheduleResponse)
async def get_schedule(schedule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.put("/{schedule_id}", response_model=ScanScheduleResponse)
async def update_schedule(
    schedule_id: str,
    schedule_in: ScanScheduleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    update_data = schedule_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(schedule, field, value)
    schedule.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(schedule)

    # Re-sync with scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler:
        await scheduler.remove_schedule(schedule_id)
        if schedule.enabled:
            await scheduler.add_schedule(schedule)

    return schedule


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Remove from scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler:
        await scheduler.remove_schedule(schedule_id)

    await db.delete(schedule)


@router.post("/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule.enabled = not schedule.enabled
    schedule.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(schedule)

    # Update scheduler
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler:
        await scheduler.toggle_schedule(schedule_id, schedule.enabled)

    return {"id": schedule.id, "enabled": schedule.enabled}


@router.post("/{schedule_id}/run-now")
async def run_now(
    schedule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    scheduler = getattr(request.app.state, "scheduler", None)
    if not scheduler:
        raise HTTPException(status_code=500, detail="Scheduler not available")

    # Run in background to avoid blocking the request
    import asyncio
    asyncio.create_task(scheduler.run_now(schedule_id))

    return {"status": "triggered", "schedule_id": schedule_id}
