import asyncio
import json
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.services.report_service import ReportService
from app.evidence.artifact_store import ArtifactStore

REPORT_TIMEOUT_SECONDS = 120

router = APIRouter()


class ReportGenerateRequest(BaseModel):
    report_type: str = "html"  # html, pdf, json, csv
    run_id: str | None = None
    title: str = "Risk Assessment Report"


@router.get("/summary")
async def get_summary(db: AsyncSession = Depends(get_db)):
    """Get executive summary with counts and breakdowns."""
    service = ReportService(db)
    return await service.get_summary()


@router.post("/generate")
async def generate_report(request: ReportGenerateRequest, db: AsyncSession = Depends(get_db)):
    """Generate a report."""
    try:
        return await asyncio.wait_for(
            _build_report(request, db),
            timeout=REPORT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Report generation timed out after {REPORT_TIMEOUT_SECONDS}s",
        )


async def _build_report(request: ReportGenerateRequest, db: AsyncSession):
    report_service = ReportService(db)
    artifact_store = ArtifactStore(db)

    # Gather all data
    summary = await report_service.get_summary(request.run_id)

    REPORT_LIMIT = 5000  # Safety cap per entity type

    assets_result = await db.execute(select(Asset).order_by(Asset.ip_address).limit(REPORT_LIMIT))
    assets = [
        {
            "ip_address": a.ip_address, "hostname": a.hostname,
            "asset_type": a.asset_type, "zone": a.zone,
            "criticality": a.criticality, "os_guess": a.os_guess,
            "vendor": a.vendor,
        }
        for a in assets_result.scalars().all()
    ]

    findings_result = await db.execute(select(Finding).order_by(Finding.severity.desc()).limit(REPORT_LIMIT))
    findings = [
        {
            "title": f.title, "severity": f.severity,
            "category": f.category, "description": f.description,
            "source_tool": f.source_tool, "remediation": f.remediation,
            "evidence": f.raw_output_snippet, "status": f.status,
        }
        for f in findings_result.scalars().all()
    ]

    risks_result = await db.execute(select(Risk).order_by(Risk.risk_level.desc()).limit(REPORT_LIMIT))
    risks = [
        {
            "scenario": r.scenario, "likelihood": r.likelihood,
            "impact": r.impact, "risk_level": r.risk_level,
            "treatment": r.treatment, "status": r.status,
            "confidentiality_impact": r.confidentiality_impact,
            "integrity_impact": r.integrity_impact,
            "availability_impact": r.availability_impact,
        }
        for r in risks_result.scalars().all()
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
        "title": request.title,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": summary,
        "assets": assets,
        "findings": findings,
        "risks": risks,
        "mitre_mappings": mitre_mappings,
    }

    report_id = str(uuid.uuid4())

    if request.report_type == "html":
        try:
            from mcp_servers.reporting.html_report import HTMLReportGenerator
        except ImportError:
            import sys
            from pathlib import Path
            project_root = str(Path(__file__).resolve().parents[3])
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            from mcp_servers.reporting.html_report import HTMLReportGenerator
        generator = HTMLReportGenerator()
        html_content = generator.generate(report_data)

        await artifact_store.store(
            content=html_content,
            artifact_type="report",
            tool_name="report_generator",
            target="full_report",
            run_id=request.run_id,
            command=f"generate_report type=html",
            parameters={"report_type": "html", "report_id": report_id},
        )

        return {
            "report_id": report_id,
            "report_type": "html",
            "status": "completed",
            "summary": summary,
        }

    elif request.report_type == "json":
        content = json.dumps(report_data, indent=2, default=str)
        await artifact_store.store(
            content=content,
            artifact_type="report",
            tool_name="report_generator",
            target="full_report",
            run_id=request.run_id,
            command="generate_report type=json",
            parameters={"report_type": "json", "report_id": report_id},
        )
        return {
            "report_id": report_id,
            "report_type": "json",
            "status": "completed",
            "data": report_data,
        }

    elif request.report_type == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Title", "Severity", "Category", "Status", "Source", "Remediation"])
        for f in findings:
            writer.writerow([
                f["title"], f["severity"], f["category"],
                f["status"], f["source_tool"], f.get("remediation", ""),
            ])
        csv_content = output.getvalue()

        await artifact_store.store(
            content=csv_content,
            artifact_type="report",
            tool_name="report_generator",
            target="findings_csv",
            run_id=request.run_id,
            command="generate_report type=csv",
            parameters={"report_type": "csv", "report_id": report_id},
        )
        return {
            "report_id": report_id,
            "report_type": "csv",
            "status": "completed",
        }

    return {"status": "error", "error": f"Unknown report type: {request.report_type}"}


@router.get("/{report_id}")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Get a generated report by artifact lookup."""
    from app.models.artifact import Artifact
    result = await db.execute(
        select(Artifact).where(
            Artifact.artifact_type == "report",
            Artifact.parameters["report_id"].as_string() == report_id,
        )
    )
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_id": report_id,
        "artifact_id": artifact.id,
        "type": artifact.parameters.get("report_type", "html"),
        "generated_at": artifact.timestamp.isoformat() if artifact.timestamp else None,
        "content_hash": artifact.content_hash,
    }


@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Download a generated report."""
    from app.models.artifact import Artifact
    from pathlib import Path
    from app.config import settings

    result = await db.execute(
        select(Artifact).where(
            Artifact.artifact_type == "report",
            Artifact.parameters["report_id"].as_string() == report_id,
        )
    )
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Report not found")

    report_type = artifact.parameters.get("report_type", "html")

    # Try file first, then DB content
    file_path = (Path(settings.artifacts_dir) / artifact.filename).resolve()
    if not str(file_path).startswith(str(Path(settings.artifacts_dir).resolve())):
        raise HTTPException(status_code=403, detail="Access denied")
    if file_path.exists():
        content = file_path.read_text(encoding="utf-8")
    elif artifact.content:
        content = artifact.content
    else:
        raise HTTPException(status_code=404, detail="Report content not available")

    if report_type == "html":
        return HTMLResponse(content=content)
    elif report_type == "csv":
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.csv"},
        )
    else:
        return Response(content=content, media_type="application/json")
