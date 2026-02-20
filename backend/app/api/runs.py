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
from app.api.ws import manager

import structlog

logger = structlog.get_logger()


async def _broadcast(run_id: str, msg_type: str, message: str, **extra):
    """Broadcast a message to all WebSocket clients watching this run."""
    try:
        payload = {"type": msg_type, "message": message, "timestamp": datetime.utcnow().isoformat(), **extra}
        await manager.broadcast(run_id, payload)
    except Exception as e:
        logger.warning("WS broadcast failed", run_id=run_id, error=str(e))

router = APIRouter()


PIPELINE_STEPS = [
    "discovery", "fingerprinting", "vuln_scanning", "exploit_analysis",
    "mitre_mapping", "threat_modeling", "risk_analysis", "baseline", "reporting",
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


async def _run_step_with_timeout(coro, step_name: str, timeout: int = 120, run_id: str | None = None):
    """Run a pipeline step with a hard timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Pipeline step timed out", step=step_name, timeout=timeout)
        if run_id:
            await _broadcast(run_id, "step_warning", f"⚠ {step_name} timed out after {timeout}s — continuing", step=step_name)
        return {"status": "timeout", "step": step_name}
    except Exception as e:
        logger.error("Pipeline step error", step=step_name, error=str(e))
        raise


async def _generate_pipeline_report(db: AsyncSession, run_id: str) -> str:
    """Generate an HTML report for a completed pipeline run, returns report_id."""
    import uuid as _uuid
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.risk import Risk
    from app.models.threat import Threat
    from app.models.mitre_mapping import MitreMapping
    from app.evidence.artifact_store import ArtifactStore

    try:
        from mcp_servers.reporting.html_report import HTMLReportGenerator
    except ImportError:
        import sys
        from pathlib import Path
        project_root = str(Path(__file__).resolve().parents[3])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from mcp_servers.reporting.html_report import HTMLReportGenerator

    REPORT_LIMIT = 5000

    assets_result = await db.execute(select(Asset).order_by(Asset.ip_address).limit(REPORT_LIMIT))
    assets = [
        {
            "ip_address": a.ip_address, "hostname": a.hostname,
            "asset_type": a.asset_type, "zone": a.zone,
            "criticality": a.criticality, "os_guess": a.os_guess,
            "vendor": a.vendor,
            "open_ports": (a.exposure or {}).get("open_ports", []),
        }
        for a in assets_result.scalars().all()
    ]

    findings_result = await db.execute(select(Finding).order_by(Finding.severity.desc()).limit(REPORT_LIMIT))
    findings = [
        {
            "title": f.title, "severity": f.severity,
            "category": f.category, "description": f.description,
            "source_tool": f.source_tool, "source_check": getattr(f, "source_check", ""),
            "remediation": f.remediation,
            "evidence": f.raw_output_snippet, "status": f.status,
            "cve_ids": f.cve_ids or [],
        }
        for f in findings_result.scalars().all()
    ]

    risks_result = await db.execute(select(Risk).order_by(Risk.risk_level.desc()).limit(REPORT_LIMIT))
    risks = [
        {
            "scenario": r.scenario, "likelihood": r.likelihood,
            "impact": r.impact, "risk_level": r.risk_level,
            "treatment": r.treatment, "status": r.status,
            "recommended_treatment": r.treatment,
        }
        for r in risks_result.scalars().all()
    ]

    threats_result = await db.execute(select(Threat).order_by(Threat.c4_level, Threat.confidence.desc()).limit(REPORT_LIMIT))
    threats = [
        {
            "title": t.title, "description": t.description,
            "threat_type": t.threat_type, "zone": t.zone,
            "confidence": t.confidence, "c4_level": t.c4_level or "component",
            "stride_category_detail": t.stride_category_detail,
            "trust_boundary": t.trust_boundary,
        }
        for t in threats_result.scalars().all()
    ]

    mitre_result = await db.execute(select(MitreMapping).limit(REPORT_LIMIT))
    mitre_mappings = [
        {
            "technique_id": m.technique_id, "technique_name": m.technique_name,
            "tactic": m.tactic, "confidence": m.confidence,
        }
        for m in mitre_result.scalars().all()
    ]

    report_data = {
        "assets": assets,
        "findings": findings,
        "risks": risks,
        "threats": threats,
        "mitre_mappings": mitre_mappings,
        "metadata": {
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "scope": "Full pipeline assessment",
        },
    }

    generator = HTMLReportGenerator()
    html_content = generator.generate(report_data)

    report_id = str(_uuid.uuid4())
    artifact_store = ArtifactStore(db)
    await artifact_store.store(
        content=html_content,
        artifact_type="report",
        tool_name="report_generator",
        target="full_report",
        run_id=run_id,
        command="pipeline_report_generation",
        parameters={"report_type": "html", "report_id": report_id},
    )
    await db.commit()

    logger.info("Pipeline report generated", run_id=run_id, report_id=report_id)
    return report_id


async def _execute_pipeline(run_id: str, scope: dict):
    """Execute the full assessment pipeline in the background."""
    import asyncio
    import uuid
    from app.services.discovery_service import DiscoveryService, FingerprintService
    from app.services.vuln_scan_service import VulnScanService
    from app.services.exploit_service import ExploitEnrichmentService
    from app.services.mitre_service import MitreService
    from app.services.threat_service import ThreatService
    from app.services.risk_analysis_service import RiskAnalysisService
    from app.services.drift_service import DriftService

    # Small delay to ensure the creating request has committed
    await asyncio.sleep(0.5)

    # Per-step timeouts (seconds)
    STEP_TIMEOUTS = {
        "discovery": 90,
        "fingerprinting": 90,
        "vuln_scanning": 120,
        "exploit_analysis": 30,
        "mitre_mapping": 30,
        "threat_modeling": 60,
        "risk_analysis": 30,
        "baseline": 15,
        "reporting": 60,
    }

    STEP_LABELS = {
        "discovery": ("Asset Discovery", "Scanning {subnet} for live hosts..."),
        "fingerprinting": ("Fingerprinting", "Identifying services and OS on discovered hosts..."),
        "vuln_scanning": ("Vulnerability Scanning", "Running vulnerability checks on assets..."),
        "exploit_analysis": ("Exploit Analysis", "Assessing exploitability of findings..."),
        "mitre_mapping": ("MITRE Mapping", "Mapping findings to ATT&CK techniques..."),
        "threat_modeling": ("Threat Modeling", "Running C4/STRIDE threat analysis..."),
        "risk_analysis": ("Risk Analysis", "Calculating risk levels for all scenarios..."),
        "baseline": ("Baseline Snapshot", "Creating drift detection baseline..."),
        "reporting": ("Report Generation", "Generating assessment report..."),
    }

    async with async_session() as db:
        completed_steps: list[str] = []
        try:
            subnet = (scope.get("subnets") or ["192.168.178.0/24"])[0]
            await _broadcast(run_id, "pipeline_start", f"Pipeline started — target: {subnet}", steps=list(STEP_LABELS.keys()))

            # Step 1: Discovery
            await _update_run_step(db, run_id, "discovery", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["discovery"][1].format(subnet=subnet), step="discovery")
            logger.info("Pipeline step: discovery", run_id=run_id)
            discovery_svc = DiscoveryService(db)
            disc_result = await _run_step_with_timeout(
                discovery_svc.run_discovery(subnet=subnet, run_id=run_id, timeout=60),
                "discovery", STEP_TIMEOUTS["discovery"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("discovery")
            count = disc_result.get("hosts_found", "?") if isinstance(disc_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Discovery complete — found {count} hosts", step="discovery")

            # Step 2: Fingerprinting
            await _update_run_step(db, run_id, "fingerprinting", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["fingerprinting"][1], step="fingerprinting")
            logger.info("Pipeline step: fingerprinting", run_id=run_id)
            fingerprint_svc = FingerprintService(db)
            fp_result = await _run_step_with_timeout(
                fingerprint_svc.run_fingerprinting(run_id=run_id, timeout=60),
                "fingerprinting", STEP_TIMEOUTS["fingerprinting"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("fingerprinting")
            fp_count = fp_result.get("assets_fingerprinted", "?") if isinstance(fp_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Fingerprinting complete — {fp_count} assets profiled", step="fingerprinting")

            # Step 3: Vulnerability Scanning
            await _update_run_step(db, run_id, "vuln_scanning", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["vuln_scanning"][1], step="vuln_scanning")
            logger.info("Pipeline step: vuln_scanning", run_id=run_id)
            vuln_svc = VulnScanService(db)
            vs_result = await _run_step_with_timeout(
                vuln_svc.run_vuln_scan(run_id=run_id, timeout=100),
                "vuln_scanning", STEP_TIMEOUTS["vuln_scanning"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("vuln_scanning")
            vs_count = vs_result.get("findings_created", "?") if isinstance(vs_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Vulnerability scan complete — {vs_count} findings", step="vuln_scanning")

            # Step 4: Exploit Analysis
            await _update_run_step(db, run_id, "exploit_analysis", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["exploit_analysis"][1], step="exploit_analysis")
            logger.info("Pipeline step: exploit_analysis", run_id=run_id)
            exploit_svc = ExploitEnrichmentService(db)
            ea_result = await _run_step_with_timeout(
                exploit_svc.run_enrichment(run_id=run_id),
                "exploit_analysis", STEP_TIMEOUTS["exploit_analysis"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("exploit_analysis")
            ea_count = ea_result.get("enriched", "?") if isinstance(ea_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Exploit analysis complete — {ea_count} findings enriched", step="exploit_analysis")

            # Step 5: MITRE Mapping
            await _update_run_step(db, run_id, "mitre_mapping", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["mitre_mapping"][1], step="mitre_mapping")
            logger.info("Pipeline step: mitre_mapping", run_id=run_id)
            mitre_svc = MitreService(db)
            mm_result = await _run_step_with_timeout(
                mitre_svc.run_mapping(run_id=run_id),
                "mitre_mapping", STEP_TIMEOUTS["mitre_mapping"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("mitre_mapping")
            mm_count = mm_result.get("mappings_created", "?") if isinstance(mm_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"MITRE mapping complete — {mm_count} techniques mapped", step="mitre_mapping")

            # Step 6: Threat Modeling
            await _update_run_step(db, run_id, "threat_modeling", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["threat_modeling"][1], step="threat_modeling")
            logger.info("Pipeline step: threat_modeling", run_id=run_id)
            threat_svc = ThreatService(db)

            async def _threat_broadcast(msg: str):
                await _broadcast(run_id, "step_detail", msg, step="threat_modeling")

            tm_result = await _run_step_with_timeout(
                threat_svc.run_full_threat_modeling(run_id=run_id, broadcast_fn=_threat_broadcast),
                "threat_modeling", STEP_TIMEOUTS["threat_modeling"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("threat_modeling")
            tm_count = tm_result.get("threats_created", "?") if isinstance(tm_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Threat modeling complete — {tm_count} threats identified", step="threat_modeling")

            # Step 7: Risk Analysis
            await _update_run_step(db, run_id, "risk_analysis", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["risk_analysis"][1], step="risk_analysis")
            logger.info("Pipeline step: risk_analysis", run_id=run_id)
            risk_svc = RiskAnalysisService(db)
            ra_result = await _run_step_with_timeout(
                risk_svc.run_risk_analysis(run_id=run_id),
                "risk_analysis", STEP_TIMEOUTS["risk_analysis"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("risk_analysis")
            ra_count = ra_result.get("risks_created", "?") if isinstance(ra_result, dict) else "?"
            await _broadcast(run_id, "step_complete", f"Risk analysis complete — {ra_count} risk scenarios", step="risk_analysis")

            # Step 8: Baseline
            await _update_run_step(db, run_id, "baseline", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["baseline"][1], step="baseline")
            logger.info("Pipeline step: baseline", run_id=run_id)
            drift_svc = DriftService(db)
            await _run_step_with_timeout(
                drift_svc.create_baseline(zone="lan", baseline_type="full", run_id=run_id),
                "baseline", STEP_TIMEOUTS["baseline"], run_id=run_id,
            )
            await db.commit()
            completed_steps.append("baseline")
            await _broadcast(run_id, "step_complete", "Baseline snapshot saved", step="baseline")

            # Pipeline-wide stale finding cleanup: mark ALL open findings
            # not observed in this run as fixed (covers all source_tools)
            try:
                from app.services.finding_service import FindingService
                finding_svc = FindingService(db)
                all_asset_ids = [a.id for a in assets] if assets else []
                pipeline_stale = await finding_svc.mark_stale_findings(run_id, all_asset_ids)
                if pipeline_stale:
                    logger.info("Pipeline stale cleanup", auto_resolved=pipeline_stale, run_id=run_id)
                await db.commit()
            except Exception as e:
                logger.warning("Pipeline stale cleanup failed", error=str(e))

            # Step 9: Report Generation
            await _update_run_step(db, run_id, "reporting", completed_steps)
            await _broadcast(run_id, "step_start", STEP_LABELS["reporting"][1], step="reporting")
            logger.info("Pipeline step: reporting", run_id=run_id)

            report_id = await _generate_pipeline_report(db, run_id)

            completed_steps.append("reporting")
            await _broadcast(run_id, "step_complete", "Assessment report generated", step="reporting")

            # Complete
            result = await db.execute(select(Run).where(Run.id == run_id))
            run = result.scalar_one_or_none()
            if run:
                run.status = "completed"
                run.current_step = "completed"
                run.steps_completed = completed_steps
                run.completed_at = datetime.utcnow()
                run.report_id = report_id
                await db.commit()
            logger.info("Pipeline completed", run_id=run_id, report_id=report_id)
            await _broadcast(run_id, "pipeline_complete", f"Pipeline finished — {len(completed_steps)}/{len(PIPELINE_STEPS)} steps completed", steps_completed=completed_steps, report_id=report_id)

        except Exception as e:
            logger.error("Pipeline failed", run_id=run_id, error=str(e), step=completed_steps[-1] if completed_steps else "init")
            await _broadcast(run_id, "error", f"Pipeline failed: {str(e)}", step=completed_steps[-1] if completed_steps else "init")
            try:
                result = await db.execute(select(Run).where(Run.id == run_id))
                run = result.scalar_one_or_none()
                if run:
                    run.status = "failed"
                    run.steps_completed = completed_steps
                    run.completed_at = datetime.utcnow()
                    await db.commit()
            except Exception as mark_err:
                logger.error("Failed to mark run as failed", run_id=run_id, error=str(mark_err))


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


async def mark_stale_runs():
    """Mark any 'running' or 'pending' runs as failed on startup (server restart means they died)."""
    async with async_session() as db:
        result = await db.execute(
            select(Run).where(Run.status.in_(["running", "pending"]))
        )
        stale_runs = result.scalars().all()
        if not stale_runs:
            return
        for run in stale_runs:
            run.status = "failed"
            run.completed_at = datetime.utcnow()
            logger.warning("Marked stale run as failed", run_id=run.id, previous_status=run.status)
        await db.commit()
        logger.info("Stale run cleanup complete", count=len(stale_runs))
