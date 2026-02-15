import asyncio
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.schedule import ScanSchedule
from app.models.run import Run
import structlog

logger = structlog.get_logger()


class SchedulerService:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._running = False

    async def start(self):
        """Start scheduler and load all enabled schedules from DB."""
        logger.info("Starting scheduler service")
        self.scheduler.start()
        self._running = True

        async with async_session() as db:
            result = await db.execute(
                select(ScanSchedule).where(ScanSchedule.enabled == True)
            )
            schedules = result.scalars().all()
            for schedule in schedules:
                self._add_job(schedule)
                logger.info("Loaded schedule", name=schedule.name, id=schedule.id)

        logger.info("Scheduler service started", job_count=len(self.scheduler.get_jobs()))

    async def stop(self):
        """Shutdown scheduler gracefully."""
        if self._running:
            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scheduler service stopped")

    def _add_job(self, schedule: ScanSchedule):
        """Create an APScheduler job from a ScanSchedule model."""
        job_id = f"schedule_{schedule.id}"

        # Remove existing job if any
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        if schedule.schedule_type == "interval" and schedule.interval_hours:
            trigger = IntervalTrigger(hours=schedule.interval_hours)
        elif schedule.schedule_type == "cron" and schedule.cron_expression:
            parts = schedule.cron_expression.strip().split()
            cron_kwargs = {}
            fields = ["minute", "hour", "day", "month", "day_of_week"]
            for i, field in enumerate(fields):
                if i < len(parts):
                    cron_kwargs[field] = parts[i]
            trigger = CronTrigger(**cron_kwargs)
        else:
            logger.warning("Invalid schedule config, skipping", id=schedule.id)
            return

        self.scheduler.add_job(
            self._execute_scan,
            trigger=trigger,
            id=job_id,
            args=[schedule.id],
            replace_existing=True,
            misfire_grace_time=300,
        )

        # Update next_run_at
        job = self.scheduler.get_job(job_id)
        if job:
            next_run = getattr(job, "next_run_time", None)
            if next_run:
                asyncio.ensure_future(self._update_next_run(schedule.id, next_run))

    async def _update_next_run(self, schedule_id: str, next_run: datetime):
        """Update next_run_at in database."""
        try:
            async with async_session() as db:
                result = await db.execute(
                    select(ScanSchedule).where(ScanSchedule.id == schedule_id)
                )
                schedule = result.scalar_one_or_none()
                if schedule:
                    schedule.next_run_at = next_run
                    await db.commit()
        except Exception as e:
            logger.error("Failed to update next_run_at", error=str(e))

    async def add_schedule(self, schedule: ScanSchedule):
        """Add a new schedule to the scheduler."""
        if schedule.enabled:
            self._add_job(schedule)

    async def remove_schedule(self, schedule_id: str):
        """Remove a schedule from the scheduler."""
        job_id = f"schedule_{schedule_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

    async def toggle_schedule(self, schedule_id: str, enabled: bool):
        """Enable or disable a schedule."""
        job_id = f"schedule_{schedule_id}"
        if enabled:
            async with async_session() as db:
                result = await db.execute(
                    select(ScanSchedule).where(ScanSchedule.id == schedule_id)
                )
                schedule = result.scalar_one_or_none()
                if schedule:
                    self._add_job(schedule)
        else:
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)

    async def _execute_scan(self, schedule_id: str):
        """Job callback: execute the scheduled scan."""
        logger.info("Executing scheduled scan", schedule_id=schedule_id)

        try:
            async with async_session() as db:
                # Load schedule
                result = await db.execute(
                    select(ScanSchedule).where(ScanSchedule.id == schedule_id)
                )
                schedule = result.scalar_one_or_none()
                if not schedule:
                    logger.error("Schedule not found", schedule_id=schedule_id)
                    return

                # Create a new Run
                run = Run(
                    status="running",
                    current_step="scheduled_scan",
                    triggered_by="schedule",
                    scope=schedule.scope or {},
                    started_at=datetime.utcnow(),
                    config_snapshot={"schedule_id": schedule_id, "scan_type": schedule.scan_type},
                )
                db.add(run)
                await db.flush()
                await db.refresh(run)
                run_id = run.id

                scan_type = schedule.scan_type
                subnet = (schedule.scope or {}).get("subnets", [None])[0] if schedule.scope else None

                # Execute scan pipeline based on scan_type
                if scan_type in ("full", "discovery"):
                    if subnet:
                        from app.services.discovery_service import DiscoveryService
                        discovery_svc = DiscoveryService(db)
                        await discovery_svc.run_discovery(subnet=subnet, run_id=run_id)

                if scan_type in ("full", "vuln_only"):
                    from app.services.vuln_scan_service import VulnScanService
                    vuln_svc = VulnScanService(db)
                    await vuln_svc.run_vuln_scan(run_id=run_id)

                if scan_type in ("full", "threat_only"):
                    from app.services.threat_service import ThreatService
                    threat_svc = ThreatService(db)
                    await threat_svc.generate_threats(run_id=run_id)

                # Update run status
                run.status = "completed"
                run.completed_at = datetime.utcnow()

                # Update schedule
                schedule.last_run_at = datetime.utcnow()
                schedule.last_run_id = run_id

                await db.commit()

                # Update next_run_at
                job = self.scheduler.get_job(f"schedule_{schedule_id}")
                if job:
                    next_run = getattr(job, "next_run_time", None)
                    if next_run:
                        schedule.next_run_at = next_run
                        await db.commit()

                logger.info("Scheduled scan completed", schedule_id=schedule_id, run_id=run_id)

        except Exception as e:
            logger.error("Scheduled scan failed", schedule_id=schedule_id, error=str(e))
            try:
                async with async_session() as db:
                    result = await db.execute(
                        select(ScanSchedule).where(ScanSchedule.id == schedule_id)
                    )
                    schedule = result.scalar_one_or_none()
                    if schedule:
                        schedule.last_run_at = datetime.utcnow()
                        await db.commit()
            except Exception:
                pass

    async def run_now(self, schedule_id: str):
        """Trigger a schedule to run immediately."""
        await self._execute_scan(schedule_id)
