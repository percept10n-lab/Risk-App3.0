import json
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.threat import Threat
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
import structlog

logger = structlog.get_logger()


class ThreatService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)

    async def run_threat_modeling(
        self, asset_id: str | None = None, run_id: str | None = None
    ) -> dict:
        """Run threat modeling for one or all assets."""
        logger.info("Starting threat modeling", asset_id=asset_id, run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="threat_modeling_start", run_id=run_id,
        )

        # Get target assets
        if asset_id:
            result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            assets = [asset] if asset else []
        else:
            result = await self.db.execute(select(Asset))
            assets = list(result.scalars().all())

        created = 0
        skipped = 0
        all_threats = []

        for asset in assets:
            try:
                threats = self._generate_threats_for_asset(asset)
                for threat_data in threats:
                    threat, is_new = await self._create_deduplicated_threat(
                        asset, threat_data
                    )
                    if is_new:
                        created += 1
                        all_threats.append(threat_data)
                    else:
                        skipped += 1
            except Exception as e:
                logger.error(
                    "Threat modeling failed for asset",
                    ip=asset.ip_address, error=str(e),
                )

        # Store artifact
        summary = {
            "threats_created": created,
            "threats_skipped_duplicate": skipped,
            "total_assets": len(assets),
        }
        await self.artifact_store.store(
            content=json.dumps(
                {"threats": all_threats, "summary": summary}, indent=2, default=str
            ),
            artifact_type="raw_output",
            tool_name="threat_service",
            target="all_assets" if not asset_id else asset_id,
            run_id=run_id,
            command=f"threat_modeling asset_id={asset_id}",
            parameters={"asset_id": asset_id},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="threat_modeling_complete", run_id=run_id,
            new_value=summary,
        )

        logger.info("Threat modeling complete", created=created, skipped=skipped)
        return {
            "status": "completed",
            "threats_created": created,
            "threats_skipped_duplicate": skipped,
            "total_assets": len(assets),
        }

    def _generate_threats_for_asset(self, asset: Asset) -> list[dict]:
        """Generate threats using rule-based logic."""
        from mcp_servers.threat_modeling.rules import ThreatRuleEngine

        engine = ThreatRuleEngine()
        exposure = asset.exposure or {}
        open_ports = []

        # Extract open ports from exposure indicators
        if exposure.get("ssh_exposed"):
            open_ports.append(22)
        if exposure.get("telnet_exposed"):
            open_ports.append(23)
        if exposure.get("ftp_exposed"):
            open_ports.append(21)
        if exposure.get("admin_ui"):
            open_ports.extend([80, 443])
        if exposure.get("smb_exposed"):
            open_ports.append(445)
        if exposure.get("upnp"):
            open_ports.append(1900)

        asset_data = {
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type or "unknown",
            "zone": asset.zone or "lan",
            "hostname": asset.hostname,
            "os_guess": asset.os_guess,
            "exposure": exposure,
            "open_ports": open_ports,
            "services": [],
            "criticality": asset.criticality or "medium",
        }

        return engine.evaluate(asset_data)

    async def _create_deduplicated_threat(
        self, asset: Asset, threat_data: dict
    ) -> tuple[Threat, bool]:
        """Create a threat if it doesn't already exist for this asset."""
        result = await self.db.execute(
            select(Threat).where(
                Threat.asset_id == asset.id,
                Threat.title == threat_data["title"],
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            return existing, False

        threat = Threat(
            asset_id=asset.id,
            title=threat_data["title"],
            description=threat_data.get("description", ""),
            threat_type=threat_data.get("threat_type", "unknown"),
            source=threat_data.get("source", "rule"),
            zone=threat_data.get("zone", asset.zone),
            trust_boundary=threat_data.get("trust_boundary"),
            confidence=threat_data.get("confidence", 0.5),
            rationale=threat_data.get("description", ""),
        )
        self.db.add(threat)
        await self.db.flush()
        return threat, True

    async def run_zone_threat_analysis(
        self, zone: str, run_id: str | None = None
    ) -> dict:
        """Run zone-level threat analysis."""
        from mcp_servers.threat_modeling.rules import ThreatRuleEngine

        engine = ThreatRuleEngine()

        result = await self.db.execute(
            select(Asset).where(Asset.zone == zone)
        )
        assets = list(result.scalars().all())
        asset_types = [a.asset_type or "unknown" for a in assets]

        threats = engine.evaluate_zone(
            zone=zone,
            asset_count=len(assets),
            asset_types=asset_types,
            has_isolation=False,
        )

        created = 0
        for threat_data in threats:
            existing = await self.db.execute(
                select(Threat).where(
                    Threat.zone == zone,
                    Threat.title == threat_data["title"],
                    Threat.asset_id.is_(None),
                )
            )
            if not existing.scalar_one_or_none():
                threat = Threat(
                    title=threat_data["title"],
                    description=threat_data.get("description", ""),
                    threat_type=threat_data.get("threat_type", "unknown"),
                    source="rule",
                    zone=zone,
                    confidence=threat_data.get("confidence", 0.5),
                    rationale=threat_data.get("description", ""),
                )
                self.db.add(threat)
                created += 1

        await self.db.flush()

        return {
            "status": "completed",
            "zone": zone,
            "threats_created": created,
            "assets_in_zone": len(assets),
        }
