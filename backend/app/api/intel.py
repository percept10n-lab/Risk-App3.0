from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.threat import Threat
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.config import settings

import httpx
import structlog

logger = structlog.get_logger()

router = APIRouter()


@router.get("/summary")
async def intel_summary(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated threat intelligence summary."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    # Total counts
    total_assets = (await db.execute(select(sa_func.count(Asset.id)))).scalar() or 0
    total_findings = (await db.execute(select(sa_func.count(Finding.id)))).scalar() or 0
    total_threats = (await db.execute(select(sa_func.count(Threat.id)))).scalar() or 0
    total_risks = (await db.execute(select(sa_func.count(Risk.id)))).scalar() or 0

    # Recent threats (in period)
    recent_threats_count = (await db.execute(
        select(sa_func.count(Threat.id)).where(Threat.created_at >= cutoff)
    )).scalar() or 0

    # Threats by type
    threat_by_type_rows = (await db.execute(
        select(Threat.threat_type, sa_func.count(Threat.id))
        .where(Threat.created_at >= cutoff)
        .group_by(Threat.threat_type)
    )).all()
    threat_by_type = {row[0]: row[1] for row in threat_by_type_rows}

    # Findings by severity (in period)
    sev_rows = (await db.execute(
        select(Finding.severity, sa_func.count(Finding.id))
        .where(Finding.created_at >= cutoff)
        .group_by(Finding.severity)
    )).all()
    findings_by_severity = {row[0]: row[1] for row in sev_rows}

    # Risk distribution
    risk_rows = (await db.execute(
        select(Risk.risk_level, sa_func.count(Risk.id))
        .group_by(Risk.risk_level)
    )).all()
    risk_distribution = {row[0]: row[1] for row in risk_rows}

    # Open critical/high findings
    open_critical_high = (await db.execute(
        select(sa_func.count(Finding.id))
        .where(Finding.severity.in_(["critical", "high"]), Finding.status == "open")
    )).scalar() or 0

    # Critical risks
    critical_risks = (await db.execute(
        select(sa_func.count(Risk.id)).where(Risk.risk_level == "critical")
    )).scalar() or 0

    # Top 10 MITRE techniques
    mitre_rows = (await db.execute(
        select(MitreMapping.technique_id, MitreMapping.technique_name, MitreMapping.tactic, sa_func.count(MitreMapping.id).label("count"))
        .group_by(MitreMapping.technique_id, MitreMapping.technique_name, MitreMapping.tactic)
        .order_by(sa_func.count(MitreMapping.id).desc())
        .limit(10)
    )).all()
    top_mitre = [
        {"technique_id": r[0], "technique_name": r[1], "tactic": r[2], "count": r[3]}
        for r in mitre_rows
    ]

    # Asset exposure — top 10 assets with most threats
    exposure_rows = (await db.execute(
        select(
            Asset.id, Asset.hostname, Asset.ip_address, Asset.criticality,
            sa_func.count(Threat.id).label("threat_count"),
        )
        .join(Threat, Threat.asset_id == Asset.id)
        .group_by(Asset.id, Asset.hostname, Asset.ip_address, Asset.criticality)
        .order_by(sa_func.count(Threat.id).desc())
        .limit(10)
    )).all()
    asset_exposure = [
        {"asset_id": r[0], "hostname": r[1], "ip_address": r[2], "criticality": r[3], "threat_count": r[4]}
        for r in exposure_rows
    ]

    # Recent 20 threats
    recent_threats_result = await db.execute(
        select(Threat).order_by(Threat.created_at.desc()).limit(20)
    )
    recent_threats = [
        {
            "id": t.id, "title": t.title, "threat_type": t.threat_type,
            "confidence": t.confidence, "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in recent_threats_result.scalars().all()
    ]

    return {
        "period_days": days,
        "totals": {
            "assets": total_assets,
            "findings": total_findings,
            "threats": total_threats,
            "risks": total_risks,
        },
        "recent_threats_count": recent_threats_count,
        "threat_by_type": threat_by_type,
        "findings_by_severity": findings_by_severity,
        "risk_distribution": risk_distribution,
        "open_critical_high": open_critical_high,
        "critical_risks": critical_risks,
        "top_mitre": top_mitre,
        "asset_exposure": asset_exposure,
        "recent_threats": recent_threats,
    }


@router.get("/daily-brief")
async def daily_brief(db: AsyncSession = Depends(get_db)):
    """AI-generated or template-based daily threat brief."""
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)

    total_assets = (await db.execute(select(sa_func.count(Asset.id)))).scalar() or 0
    new_findings_24h = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.created_at >= cutoff_24h)
    )).scalar() or 0
    new_threats_24h = (await db.execute(
        select(sa_func.count(Threat.id)).where(Threat.created_at >= cutoff_24h)
    )).scalar() or 0
    open_critical = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.severity == "critical", Finding.status == "open")
    )).scalar() or 0
    open_high = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.severity == "high", Finding.status == "open")
    )).scalar() or 0
    critical_risks = (await db.execute(
        select(sa_func.count(Risk.id)).where(Risk.risk_level == "critical")
    )).scalar() or 0

    stats_context = {
        "total_assets": total_assets,
        "new_findings_24h": new_findings_24h,
        "new_threats_24h": new_threats_24h,
        "open_critical": open_critical,
        "open_high": open_high,
        "critical_risks": critical_risks,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
    }

    # Try AI-generated brief
    ai_generated = False
    brief = ""
    if settings.ai_api_key or settings.ai_provider == "ollama":
        try:
            brief = await _generate_ai_brief(stats_context)
            ai_generated = True
        except Exception as e:
            logger.warning("AI brief generation failed, using template", error=str(e))

    if not brief:
        brief = _generate_template_brief(stats_context)

    return {
        "brief": brief,
        "ai_generated": ai_generated,
        "stats": stats_context,
    }


async def _generate_ai_brief(stats: dict) -> str:
    """Generate brief using configured AI provider."""
    prompt = (
        f"You are a cybersecurity analyst. Write a concise daily threat intelligence brief (3-5 paragraphs, markdown) "
        f"for a home network security platform.\n\n"
        f"Current stats as of {stats['date']}:\n"
        f"- Total monitored assets: {stats['total_assets']}\n"
        f"- New findings (24h): {stats['new_findings_24h']}\n"
        f"- New threats (24h): {stats['new_threats_24h']}\n"
        f"- Open critical findings: {stats['open_critical']}\n"
        f"- Open high findings: {stats['open_high']}\n"
        f"- Critical risk scenarios: {stats['critical_risks']}\n\n"
        f"Include: executive summary, key concerns, recommended actions. Be specific and actionable."
    )

    if settings.ai_provider == "ollama":
        url = f"{settings.ai_base_url}/api/generate"
        payload = {"model": settings.ai_model, "prompt": prompt, "stream": False}
    else:
        url = f"{settings.ai_base_url}/v1/chat/completions"
        payload = {
            "model": settings.ai_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }

    headers = {}
    if settings.ai_api_key:
        headers["Authorization"] = f"Bearer {settings.ai_api_key}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    if settings.ai_provider == "ollama":
        return data.get("response", "")
    else:
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")


def _generate_template_brief(stats: dict) -> str:
    """Generate a template-based brief when AI is unavailable."""
    severity_label = "stable"
    if stats["open_critical"] > 0:
        severity_label = "elevated"
    elif stats["open_high"] > 3:
        severity_label = "moderate"

    brief = f"## Daily Threat Intelligence Brief — {stats['date']}\n\n"
    brief += f"### Executive Summary\n\n"
    brief += (
        f"The network security posture is **{severity_label}**. "
        f"Currently monitoring **{stats['total_assets']}** assets. "
    )

    if stats["new_findings_24h"] > 0 or stats["new_threats_24h"] > 0:
        brief += (
            f"In the last 24 hours, **{stats['new_findings_24h']}** new findings "
            f"and **{stats['new_threats_24h']}** new threats were identified.\n\n"
        )
    else:
        brief += "No new findings or threats in the last 24 hours.\n\n"

    brief += "### Key Metrics\n\n"
    brief += f"| Metric | Count |\n|---|---|\n"
    brief += f"| Open Critical Findings | {stats['open_critical']} |\n"
    brief += f"| Open High Findings | {stats['open_high']} |\n"
    brief += f"| Critical Risk Scenarios | {stats['critical_risks']} |\n"
    brief += f"| New Findings (24h) | {stats['new_findings_24h']} |\n"
    brief += f"| New Threats (24h) | {stats['new_threats_24h']} |\n\n"

    if stats["open_critical"] > 0:
        brief += "### Recommended Actions\n\n"
        brief += f"- **Immediate**: Address {stats['open_critical']} critical finding(s) — these represent active risk to the network\n"
        brief += f"- **Short-term**: Review and triage {stats['open_high']} high-severity findings within SLA\n"
        brief += f"- **Ongoing**: Monitor {stats['critical_risks']} critical risk scenarios for changes\n"
    elif stats["open_high"] > 0:
        brief += "### Recommended Actions\n\n"
        brief += f"- Review and prioritize {stats['open_high']} open high-severity findings\n"
        brief += "- Run the AI Copilot triage for automated prioritization\n"
    else:
        brief += "### Status\n\n"
        brief += "No critical or high-severity findings require immediate attention. Continue routine monitoring.\n"

    return brief
