import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.config import settings
from app.database import init_db
from app.api import (
    assets, findings, threats, risks, mitre,
    runs, pentest, vulnmgmt, reports, copilot,
    drift, settings as settings_api, ws,
    discovery, audit, artifacts, nmap, schedules
)
from app.services.scheduler_service import SchedulerService
from app.api.runs import mark_stale_runs

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting application", version=settings.app_version)
    await init_db()
    os.makedirs(settings.artifacts_dir, exist_ok=True)

    # Mark any runs left in running/pending state as failed (stale from previous crash)
    try:
        await mark_stale_runs()
    except Exception as e:
        logger.error("Stale run cleanup failed", error=str(e))

    # Start scheduler
    scheduler = SchedulerService()
    try:
        await scheduler.start()
        app.state.scheduler = scheduler
    except Exception as e:
        logger.error("Failed to start scheduler", error=str(e))
        app.state.scheduler = None

    yield

    # Stop scheduler
    if getattr(app.state, "scheduler", None):
        await app.state.scheduler.stop()
    logger.info("Shutting down application")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(threats.router, prefix="/api/threats", tags=["threats"])
app.include_router(risks.router, prefix="/api/risks", tags=["risks"])
app.include_router(mitre.router, prefix="/api/mitre", tags=["mitre"])
app.include_router(runs.router, prefix="/api/runs", tags=["runs"])
app.include_router(pentest.router, prefix="/api/pentest", tags=["pentest"])
app.include_router(vulnmgmt.router, prefix="/api/vulns", tags=["vulnerability-management"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(copilot.router, prefix="/api/copilot", tags=["copilot"])
app.include_router(drift.router, prefix="/api/drift", tags=["drift"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["settings"])
app.include_router(ws.router, prefix="/api/ws", tags=["websocket"])
app.include_router(discovery.router, prefix="/api/scan", tags=["scanning"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(artifacts.router, prefix="/api/artifacts", tags=["artifacts"])
app.include_router(nmap.router, prefix="/api/nmap", tags=["nmap"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": settings.app_version}
