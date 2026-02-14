from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.threat import Threat


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_summary(self, run_id: str | None = None) -> dict:
        asset_count = (await self.db.execute(select(func.count(Asset.id)))).scalar() or 0
        finding_count = (await self.db.execute(select(func.count(Finding.id)))).scalar() or 0
        risk_count = (await self.db.execute(select(func.count(Risk.id)))).scalar() or 0
        threat_count = (await self.db.execute(select(func.count(Threat.id)))).scalar() or 0

        severity_result = await self.db.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
        )
        severity_breakdown = dict(severity_result.all())

        risk_result = await self.db.execute(
            select(Risk.risk_level, func.count(Risk.id)).group_by(Risk.risk_level)
        )
        risk_breakdown = dict(risk_result.all())

        return {
            "total_assets": asset_count,
            "total_findings": finding_count,
            "total_risks": risk_count,
            "total_threats": threat_count,
            "severity_breakdown": severity_breakdown,
            "risk_breakdown": risk_breakdown,
        }
