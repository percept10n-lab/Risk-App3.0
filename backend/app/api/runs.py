import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db, async_session
from app.models.run import Run
from app.models.audit_event import AuditEvent
from app.schemas.run import RunCreate, RunResponse
from app.schemas.common import PaginatedResponse

import structlog

logger = structlog.get_logger()

router = APIRouter()


PIPELINE_STEPS = [
    "discovery", "fingerprinting", "threat_modeling", "vuln_scanning",
    "exploit_analysis", "mitre_mapping", "risk_analysis", "baseline",
]


async def _update_run_step(db: AsyncSession, run_id: str, step: str, steps_completed: list[str]):
    """Update run record with current step progress."""
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        return
    run.status = "running"
    run.current_step = step
    run.steps_completed = steps_completed
    if not run.started_at:
        run.started_at = datetime.utcnow()
    await db.commit()


async def _run_step_with_timeout(coro, step_name: str, timeout: int = 120):
    """Run a pipeline step with a hard timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Pipeline step timed out", step=step_name, timeout=timeout)
        return {"status": "timeout", "step": step_name}
    except Exception as e:
        logger.error("Pipeline step error", step=step_name, error=str(e))
        raise


async def _execute_pipeline(run_id: str, scope: dict):
    """Execute the full assessment pipeline in the background."""
    import asyncio
    from app.services.discovery_service import DiscoveryService, FingerprintService
    from app.services.threat_service import ThreatService
    from app.services.vuln_scan_service import VulnScanService
    from app.services.exploit_service import ExploitEnrichmentService
    from app.services.mitre_service import MitreService
    from app.services.risk_analysis_service import RiskAnalysisService
    from app.services.drift_service import DriftService

    # Small delay to ensure the creating request has committed
    await asyncio.sleep(0.5)

    # Per-step timeouts (seconds)
    STEP_TIMEOUTS = {
        "discovery": 90,
        "fingerprinting": 90,
        "threat_modeling": 30,
        "vuln_scanning": 90,
        "exploit_analysis": 30,
        "mitre_mapping": 30,
        "risk_analysis": 30,
        "baseline": 15,
    }

    async with async_session() as db:
        completed_steps: list[str] = []
        try:
            subnet = (scope.get("subnets") or ["192.168.1.0/24"])[0]

            # Step 1: Discovery
            await _update_run_step(db, run_id, "discovery", completed_steps)
            logger.info("Pipeline step: discovery", run_id=run_id)
            discovery_svc = DiscoveryService(db)
            await _run_step_with_timeout(
                discovery_svc.run_discovery(subnet=subnet, run_id=run_id, timeout=60),
                "discovery", STEP_TIMEOUTS["discovery"],
            )
            await db.commit()
            completed_steps.append("discovery")

            # Step 2: Fingerprinting
            await _update_run_step(db, run_id, "fingerprinting", completed_steps)
            logger.info("Pipeline step: fingerprinting", run_id=run_id)
            fingerprint_svc = FingerprintService(db)
            await _run_step_with_timeout(
                fingerprint_svc.run_fingerprinting(run_id=run_id, timeout=60),
                "fingerprinting", STEP_TIMEOUTS["fingerprinting"],
            )
            await db.commit()
            completed_steps.append("fingerprinting")

            # Step 3: Threat Modeling
            await _update_run_step(db, run_id, "threat_modeling", completed_steps)
            logger.info("Pipeline step: threat_modeling", run_id=run_id)
            threat_svc = ThreatService(db)
            await _run_step_with_timeout(
                threat_svc.run_threat_modeling(run_id=run_id),
                "threat_modeling", STEP_TIMEOUTS["threat_modeling"],
            )
            await db.commit()
            completed_steps.append("threat_modeling")

            # Step 4: Vulnerability Scanning
            await _update_run_step(db, run_id, "vuln_scanning", completed_steps)
            logger.info("Pipeline step: vuln_scanning", run_id=run_id)
            vuln_svc = VulnScanService(db)
            await _run_step_with_timeout(
                vuln_svc.run_vuln_scan(run_id=run_id, timeout=60),
                "vuln_scanning", STEP_TIMEOUTS["vuln_scanning"],
            )
            await db.commit()
            completed_steps.append("vuln_scanning")

            # Step 5: Exploit Analysis
            await _update_run_step(db, run_id, "exploit_analysis", completed_steps)
            logger.info("Pipeline step: exploit_analysis", run_id=run_id)
            exploit_svc = ExploitEnrichmentService(db)
            await _run_step_with_timeout(
                exploit_svc.run_enrichment(run_id=run_id),
                "exploit_analysis", STEP_TIMEOUTS["exploit_analysis"],
            )
            await db.commit()
            completed_steps.append("exploit_analysis")

            # Step 6: MITRE Mapping
            await _update_run_step(db, run_id, "mitre_mapping", completed_steps)
            logger.info("Pipeline step: mitre_mapping", run_id=run_id)
            mitre_svc = MitreService(db)
            await _run_step_with_timeout(
                mitre_svc.run_mapping(run_id=run_id),
                "mitre_mapping", STEP_TIMEOUTS["mitre_mapping"],
            )
            await db.commit()
            completed_steps.append("mitre_mapping")

            # Step 7: Risk Analysis
            await _update_run_step(db, run_id, "risk_analysis", completed_steps)
            logger.info("Pipeline step: risk_analysis", run_id=run_id)
            risk_svc = RiskAnalysisService(db)
            await _run_step_with_timeout(
                risk_svc.run_risk_analysis(run_id=run_id),
                "risk_analysis", STEP_TIMEOUTS["risk_analysis"],
            )
            await db.commit()
            completed_steps.append("risk_analysis")

            # Step 8: Baseline
            await _update_run_step(db, run_id, "baseline", completed_steps)
            logger.info("Pipeline step: baseline", run_id=run_id)
            drift_svc = DriftService(db)
            await _run_step_with_timeout(
                drift_svc.create_baseline(zone="lan", baseline_type="full", run_id=run_id),
                "baseline", STEP_TIMEOUTS["baseline"],
            )
            await db.commit()
            completed_steps.append("baseline")

            # Complete
            result = await db.execute(select(Run).where(Run.id == run_id))
            run = result.scalar_one_or_none()
            if run:
                run.status = "completed"
                run.current_step = "completed"
                run.steps_completed = completed_steps
                run.completed_at = datetime.utcnow()
                await db.commit()
            logger.info("Pipeline completed", run_id=run_id)

        except Exception as e:
            logger.error("Pipeline failed", run_id=run_id, error=str(e), step=completed_steps[-1] if completed_steps else "init")
            try:
                result = await db.execute(select(Run).where(Run.id == run_id))
                run = result.scalar_one_or_none()
                if run:
                    run.status = "failed"
                    run.steps_completed = completed_steps
                    run.completed_at = datetime.utcnow()
                    await db.commit()
            except Exception:
                pass


@router.get("", response_model=PaginatedResponse[RunResponse])
async def list_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Run)
    count_query = select(sa_func.count(Run.id))
    if status:
        query = query.where(Run.status == status)
        count_query = count_query.where(Run.status == status)
    total = (await db.execute(count_query)).scalar() or 0
    result = await db.execute(query.offset((page - 1) * page_size).limit(page_size).order_by(Run.created_at.desc()))
    return PaginatedResponse(items=result.scalars().all(), total=total, page=page, page_size=page_size)


@router.post("", response_model=RunResponse, status_code=201)
async def create_run(
    run_in: RunCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create a new assessment run and start the pipeline in the background."""
    run = Run(**run_in.model_dump())
    db.add(run)
    await db.flush()
    await db.refresh(run)

    # Commit now so the background task can access the run
    await db.commit()

    # Launch the pipeline in the background
    background_tasks.add_task(_execute_pipeline, run.id, run_in.scope)

    return run


@router.get("/{run_id}", response_model=RunResponse)
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.post("/{run_id}/pause")
async def pause_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != "running":
        raise HTTPException(status_code=400, detail="Can only pause running runs")
    run.status = "paused"
    audit = AuditEvent(event_type="run_control", entity_type="run", entity_id=run_id, actor="user", action="pause")
    db.add(audit)
    return {"status": "paused"}


@router.post("/{run_id}/resume")
async def resume_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != "paused":
        raise HTTPException(status_code=400, detail="Can only resume paused runs")
    run.status = "running"
    audit = AuditEvent(event_type="run_control", entity_type="run", entity_id=run_id, actor="user", action="resume")
    db.add(audit)
    return {"status": "running"}


@router.post("/{run_id}/cancel")
async def cancel_run(run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail="Run already finished")
    run.status = "cancelled"
    run.completed_at = datetime.utcnow()
    audit = AuditEvent(event_type="run_control", entity_type="run", entity_id=run_id, actor="user", action="cancel")
    db.add(audit)
    return {"status": "cancelled"}


@router.post("/step/{step_name}")
async def execute_step(step_name: str, run_id: str | None = None, db: AsyncSession = Depends(get_db)):
    return {"status": "accepted", "step": step_name, "message": f"Step '{step_name}' queued for execution"}
