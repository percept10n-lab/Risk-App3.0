import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db, async_session
from app.models.finding import Finding
from app.models.run import Run
from app.services.nmap_service import NmapService
import structlog

router = APIRouter()
logger = structlog.get_logger()

# In-memory pipeline status store (keyed by run_id)
_pipeline_status: dict[str, dict] = {}


class CustomScanRequest(BaseModel):
    target: str
    nmap_args: str = "-sT"
    timeout: int = 600
    auto_pipeline: bool = True


async def _run_pipeline_background(target: str, nmap_args: str, run_id: str, timeout: int):
    """Background task: run full pipeline with a fresh DB session."""
    _pipeline_status[run_id] = {"status": "running", "step": "nmap_scan"}
    try:
        async with async_session() as db:
            service = NmapService(db)

            # Validate before running
            if not service.validate_scope(target):
                _pipeline_status[run_id] = {
                    "status": "error",
                    "error": f"Target {target} is outside allowed scope (RFC 1918 only)",
                }
                await _mark_run_status(run_id, "failed")
                return

            valid, msg = service.validate_nmap_args(nmap_args)
            if not valid:
                _pipeline_status[run_id] = {"status": "error", "error": f"Invalid nmap arguments: {msg}"}
                await _mark_run_status(run_id, "failed")
                return

            result = await service.run_full_pipeline(target, nmap_args, run_id, timeout)
            _pipeline_status[run_id] = {
                "status": "completed",
                "result": {
                    "steps": result.get("steps", {}),
                    "findings_created": result.get("findings_created", 0),
                    "total_findings": result.get("total_findings", 0),
                    "assets_imported": result.get("import_result", {}).get("imported", 0),
                    "assets_updated": result.get("import_result", {}).get("updated", 0),
                },
            }
            await _mark_run_status(run_id, "completed")
    except Exception as e:
        logger.error("Background pipeline failed", run_id=run_id, error=str(e))
        _pipeline_status[run_id] = {"status": "error", "error": str(e)}
        await _mark_run_status(run_id, "failed")


async def _run_scan_only_background(target: str, nmap_args: str, run_id: str, timeout: int):
    """Background task: run scan + import only (no full pipeline)."""
    _pipeline_status[run_id] = {"status": "running", "step": "nmap_scan"}
    try:
        async with async_session() as db:
            service = NmapService(db)
            result = await service.execute_custom_scan(target, nmap_args, run_id, timeout)
            _pipeline_status[run_id] = {
                "status": result.get("status", "completed"),
                "result": {
                    "findings_created": result.get("findings_created", 0),
                    "total_findings": result.get("total_findings", 0),
                    "assets_imported": result.get("import_result", {}).get("imported", 0),
                    "assets_updated": result.get("import_result", {}).get("updated", 0),
                },
                "error": result.get("error"),
            }
            await _mark_run_status(run_id, "completed")
    except Exception as e:
        logger.error("Background scan failed", run_id=run_id, error=str(e))
        _pipeline_status[run_id] = {"status": "error", "error": str(e)}
        await _mark_run_status(run_id, "failed")


async def _mark_run_status(run_id: str, status: str):
    """Update the Run record status in the DB."""
    try:
        async with async_session() as db:
            result = await db.execute(select(Run).where(Run.id == run_id))
            run = result.scalar_one_or_none()
            if run:
                run.status = status
                if status in ("completed", "failed"):
                    run.completed_at = datetime.utcnow()
                await db.commit()
    except Exception as e:
        logger.error("Failed to update run status", run_id=run_id, error=str(e))


@router.post("/scan")
async def run_scan(request: CustomScanRequest, background_tasks: BackgroundTasks):
    """Launch nmap scan (+ optional full pipeline) as a background task."""
    run_id = str(uuid.uuid4())

    # Quick validation before launching
    service_check = NmapService.__new__(NmapService)
    if not service_check.validate_scope(request.target):
        return {"status": "error", "error": f"Target {request.target} is outside allowed scope (RFC 1918 only)"}

    valid, msg = NmapService.validate_nmap_args(request.nmap_args)
    if not valid:
        return {"status": "error", "error": f"Invalid nmap arguments: {msg}"}

    _pipeline_status[run_id] = {"status": "starting"}

    if request.auto_pipeline:
        background_tasks.add_task(
            _run_pipeline_background, request.target, request.nmap_args, run_id, request.timeout
        )
    else:
        background_tasks.add_task(
            _run_scan_only_background, request.target, request.nmap_args, run_id, request.timeout
        )

    return {
        "status": "started",
        "run_id": run_id,
        "message": f"Connect to WebSocket at /api/ws/runs/{run_id} for live output",
    }


@router.get("/status/{run_id}")
async def get_status(run_id: str):
    """Poll pipeline status (fallback when WebSocket is not available)."""
    status = _pipeline_status.get(run_id)
    if not status:
        return {"status": "unknown", "message": "No pipeline found for this run_id"}
    return status


@router.get("/results")
async def get_results(
    run_id: str | None = None,
    asset_id: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get nmap scan findings with optional filters."""
    from sqlalchemy import func as sa_func

    query = select(Finding).where(Finding.source_tool.like("nmap_%"))
    count_query = select(sa_func.count(Finding.id)).where(Finding.source_tool.like("nmap_%"))

    if run_id:
        query = query.where(Finding.run_id == run_id)
        count_query = count_query.where(Finding.run_id == run_id)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
        count_query = count_query.where(Finding.asset_id == asset_id)
    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)

    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(
        query.offset((page - 1) * page_size).limit(page_size).order_by(Finding.created_at.desc())
    )
    items = list(result.scalars().all())

    from app.schemas.finding import FindingResponse
    serialized = [FindingResponse.model_validate(f).model_dump() for f in items]

    return {"items": serialized, "total": total, "page": page, "page_size": page_size}
