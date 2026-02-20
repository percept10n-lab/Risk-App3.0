"""
Proactive Insights — urgent issues, attack chains, and recommendations.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from collections import Counter

from app.models.finding import Finding
from app.models.risk import Risk
from app.models.asset import Asset
from app.models.threat import Threat
from app.models.mitre_mapping import MitreMapping

import structlog

logger = structlog.get_logger()


class InsightsService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_insights(self) -> dict:
        """Compute proactive insights for the copilot hub."""
        urgent = await self._urgent_issues()
        chains = await self._attack_chains()
        recs = await self._recommendations()

        return {
            "urgent_issues": urgent,
            "attack_chains": chains,
            "recommendations": recs,
        }

    async def _urgent_issues(self) -> list[dict]:
        """Open critical findings + untreated critical risks."""
        issues = []

        # Critical/high open findings
        result = await self.db.execute(
            select(Finding)
            .where(Finding.severity.in_(["critical", "high"]))
            .where(Finding.status.in_(["open", "in_progress"]))
            .order_by(Finding.severity.desc())
            .limit(10)
        )
        for f in result.scalars().all():
            issues.append({
                "type": "finding",
                "severity": f.severity,
                "title": f.title,
                "id": f.id,
                "detail": f"Open {f.severity} finding: {f.title}",
            })

        # Untreated critical/high risks
        result = await self.db.execute(
            select(Risk)
            .where(Risk.risk_level.in_(["critical", "high"]))
            .where(Risk.treatment.is_(None))
            .order_by(Risk.risk_level.desc())
            .limit(10)
        )
        for r in result.scalars().all():
            issues.append({
                "type": "risk",
                "severity": r.risk_level,
                "title": r.scenario[:80] if r.scenario else "Untreated risk",
                "id": r.id,
                "detail": f"Untreated {r.risk_level} risk",
            })

        return issues

    async def _attack_chains(self) -> list[dict]:
        """Assets with multi-tactic MITRE coverage indicating attack chain potential."""
        chains = []

        # Get assets with threats mapped to multiple MITRE tactics
        result = await self.db.execute(
            select(
                MitreMapping.threat_id,
                Threat.asset_id,
                func.count(func.distinct(MitreMapping.tactic)).label("tactic_count"),
            )
            .join(Threat, MitreMapping.threat_id == Threat.id)
            .where(Threat.asset_id.isnot(None))
            .group_by(MitreMapping.threat_id, Threat.asset_id)
            .having(func.count(func.distinct(MitreMapping.tactic)) >= 2)
        )
        rows = result.all()

        # Group by asset
        asset_tactics: dict[str, set] = {}
        for _, asset_id, _ in rows:
            if asset_id:
                asset_tactics.setdefault(asset_id, set())

        if asset_tactics:
            # Get tactics per asset
            for asset_id in asset_tactics:
                tactic_result = await self.db.execute(
                    select(func.distinct(MitreMapping.tactic))
                    .join(Threat, MitreMapping.threat_id == Threat.id)
                    .where(Threat.asset_id == asset_id)
                )
                asset_tactics[asset_id] = {row[0] for row in tactic_result.all() if row[0]}

            # Get asset info
            asset_ids = list(asset_tactics.keys())[:5]
            asset_result = await self.db.execute(
                select(Asset).where(Asset.id.in_(asset_ids))
            )
            for asset in asset_result.scalars().all():
                tactics = asset_tactics.get(asset.id, set())
                if len(tactics) >= 2:
                    chains.append({
                        "asset_id": asset.id,
                        "asset_name": asset.hostname or asset.ip_address,
                        "zone": asset.zone,
                        "tactics": sorted(tactics),
                        "tactic_count": len(tactics),
                        "detail": f"{asset.hostname or asset.ip_address} has {len(tactics)} MITRE tactics mapped — potential attack chain",
                    })

        return sorted(chains, key=lambda x: x["tactic_count"], reverse=True)[:5]

    async def _recommendations(self) -> list[dict]:
        """Actionable recommendations based on data gaps."""
        recs = []

        # Assets with no findings (possibly unscanned)
        scanned_asset_ids = await self.db.execute(
            select(func.distinct(Finding.asset_id))
        )
        scanned_ids = {row[0] for row in scanned_asset_ids.all() if row[0]}

        total_assets = (await self.db.execute(select(func.count(Asset.id)))).scalar() or 0
        unscanned = total_assets - len(scanned_ids)
        if unscanned > 0:
            recs.append({
                "type": "scan",
                "priority": "high" if unscanned > 3 else "medium",
                "title": f"{unscanned} assets have not been scanned",
                "action": "Run a vulnerability scan on all assets",
            })

        # Stale findings (open for a long time — we'll just check if there are any open findings)
        open_count = (await self.db.execute(
            select(func.count(Finding.id)).where(Finding.status == "open")
        )).scalar() or 0
        if open_count > 5:
            recs.append({
                "type": "remediation",
                "priority": "high",
                "title": f"{open_count} findings remain open",
                "action": "Use the triage workflow to prioritize remediation",
            })

        # Untreated risks
        untreated = (await self.db.execute(
            select(func.count(Risk.id)).where(Risk.treatment.is_(None))
        )).scalar() or 0
        if untreated > 0:
            recs.append({
                "type": "risk",
                "priority": "medium",
                "title": f"{untreated} risks have no treatment plan",
                "action": "Review and apply risk treatments",
            })

        # No threat modeling
        threat_count = (await self.db.execute(select(func.count(Threat.id)))).scalar() or 0
        if threat_count == 0 and total_assets > 0:
            recs.append({
                "type": "threat",
                "priority": "high",
                "title": "No threat models exist",
                "action": "Run threat evaluation from the Threats page",
            })

        return recs
