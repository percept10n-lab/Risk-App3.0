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

    def _score_confidence(self, asset: Asset, threat_data: dict) -> float:
        """Compute evidence-based confidence score for a threat candidate."""
        score = 0.3  # base
        exposure = asset.exposure or {}
        threat_type = threat_data.get("threat_type", "")
        title_lower = threat_data.get("title", "").lower()

        # +0.3 if exposure data matches threat
        exposure_matches = {
            "ssh": ["ssh_exposed"],
            "telnet": ["telnet_exposed"],
            "ftp": ["ftp_exposed"],
            "smb": ["smb_exposed"],
            "upnp": ["upnp"],
            "admin": ["admin_ui"],
            "http": ["admin_ui"],
            "dns": [],
            "default": ["default_credentials"],
            "credential": ["default_credentials"],
        }
        matched = False
        for keyword, exp_keys in exposure_matches.items():
            if keyword in title_lower:
                for ek in exp_keys:
                    if exposure.get(ek):
                        matched = True
                        break
            if matched:
                break
        if matched:
            score += 0.3

        # +0.1 for high/critical asset criticality
        if (asset.criticality or "").lower() in ("high", "critical"):
            score += 0.1

        # +0.1 for WAN/DMZ zone
        if (asset.zone or "").lower() in ("wan", "dmz"):
            score += 0.1

        return min(score, 1.0)

    def _generate_threats_for_asset(self, asset: Asset) -> list[dict]:
        """Generate threats using rule-based logic."""
        try:
            from mcp_servers.threat_modeling.rules import ThreatRuleEngine
        except ImportError:
            import sys, os
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
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

        confidence = self._score_confidence(asset, threat_data)

        threat = Threat(
            asset_id=asset.id,
            title=threat_data["title"],
            description=threat_data.get("description", ""),
            threat_type=threat_data.get("threat_type", "unknown"),
            source=threat_data.get("source", "rule"),
            zone=threat_data.get("zone", asset.zone),
            trust_boundary=threat_data.get("trust_boundary"),
            confidence=confidence,
            rationale=threat_data.get("description", ""),
            c4_level=threat_data.get("c4_level"),
            stride_category_detail=threat_data.get("stride_category_detail"),
        )
        self.db.add(threat)
        await self.db.flush()
        return threat, True

    async def run_full_threat_modeling(
        self, run_id: str | None = None, broadcast_fn=None
    ) -> dict:
        """Run full C4-decomposed threat modeling with STRIDE analysis."""
        try:
            from mcp_servers.threat_modeling.rules import ThreatRuleEngine
        except ImportError:
            import sys, os
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            from mcp_servers.threat_modeling.rules import ThreatRuleEngine
        from collections import Counter

        logger.info("Starting full C4 threat modeling", run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="threat_modeling_start", run_id=run_id,
        )

        engine = ThreatRuleEngine()
        stats = {
            "threats_created": 0,
            "by_c4_level": {"system_context": 0, "container": 0, "component": 0},
            "by_stride": Counter(),
        }

        async def bc(msg):
            if broadcast_fn:
                await broadcast_fn(msg)

        # --- C4 Level 1: System Context — Trust Boundaries ---
        await bc("[C4: System Context] Analyzing trust boundaries...")

        # Define trust boundaries relevant to home networks
        boundaries = [
            ("wan", "lan", ["http", "dns", "ntp"], ["firewall", "nat"]),
            ("lan", "iot", ["mqtt", "http"], []),
            ("lan", "guest", ["dns"], []),
            ("wan", "dmz", ["http", "https"], ["firewall"]),
        ]

        for from_zone, to_zone, services, controls in boundaries:
            boundary_threats = engine.evaluate_trust_boundary(from_zone, to_zone, services, controls)
            for threat_data in boundary_threats:
                threat, is_new = await self._create_deduplicated_boundary_threat(threat_data)
                if is_new:
                    stats["threats_created"] += 1
                    stats["by_c4_level"]["system_context"] += 1
                    stats["by_stride"][threat_data.get("threat_type", "unknown")] += 1
            await bc(f"  Boundary {from_zone} <-> {to_zone}: {len(boundary_threats)} threats")

        await self.db.flush()

        # --- C4 Level 2: Container — Zone Analysis ---
        result = await self.db.execute(select(Asset))
        all_assets = list(result.scalars().all())

        # Group assets by zone
        zones: dict[str, list] = {}
        for asset in all_assets:
            z = asset.zone or "lan"
            zones.setdefault(z, []).append(asset)

        for zone, zone_assets in zones.items():
            await bc(f"[C4: Container] Analyzing {zone} zone ({len(zone_assets)} assets)...")
            asset_types = [a.asset_type or "unknown" for a in zone_assets]
            zone_threats = engine.evaluate_zone(
                zone=zone, asset_count=len(zone_assets),
                asset_types=asset_types, has_isolation=False,
            )

            zone_stride = Counter()
            for threat_data in zone_threats:
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
                        c4_level=threat_data.get("c4_level", "container"),
                        stride_category_detail=threat_data.get("stride_category_detail"),
                    )
                    self.db.add(threat)
                    stats["threats_created"] += 1
                    stats["by_c4_level"]["container"] += 1
                    tt = threat_data.get("threat_type", "unknown")
                    stats["by_stride"][tt] += 1
                    zone_stride[tt] += 1

            stride_str = " ".join(
                f"{k[0].upper()}:{v}" for k, v in sorted(zone_stride.items())
            ) or "no new threats"
            await bc(f"  {zone} zone: {stride_str}")

        await self.db.flush()

        # --- C4 Level 3: Component — Per-Asset Analysis ---
        await bc(f"[C4: Component] Analyzing {len(all_assets)} individual assets...")

        for asset in all_assets:
            try:
                threats = self._generate_threats_for_asset(asset)
                asset_created = 0
                for threat_data in threats:
                    threat, is_new = await self._create_deduplicated_threat(asset, threat_data)
                    if is_new:
                        stats["threats_created"] += 1
                        stats["by_c4_level"]["component"] += 1
                        stats["by_stride"][threat_data.get("threat_type", "unknown")] += 1
                        asset_created += 1
                if asset_created > 0:
                    hostname = asset.hostname or asset.ip_address
                    await bc(f"  {hostname} ({asset.asset_type or 'unknown'}): {asset_created} threats")
            except Exception as e:
                logger.error("Threat modeling failed for asset", ip=asset.ip_address, error=str(e))

        await self.db.flush()

        # Store artifact
        summary = {
            "threats_created": stats["threats_created"],
            "by_c4_level": stats["by_c4_level"],
            "by_stride": dict(stats["by_stride"]),
            "total_assets": len(all_assets),
        }
        await self.artifact_store.store(
            content=json.dumps(summary, indent=2, default=str),
            artifact_type="raw_output",
            tool_name="threat_service_c4",
            target="full_c4_analysis",
            run_id=run_id,
            command="run_full_threat_modeling",
            parameters={"run_id": run_id},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="threat_modeling_complete", run_id=run_id,
            new_value=summary,
        )

        logger.info("Full C4 threat modeling complete", **summary)
        return {"status": "completed", **summary}

    async def _create_deduplicated_boundary_threat(self, threat_data: dict) -> tuple:
        """Create a trust boundary threat if it doesn't already exist."""
        boundary = threat_data.get("trust_boundary")
        result = await self.db.execute(
            select(Threat).where(
                Threat.trust_boundary == boundary,
                Threat.title == threat_data["title"],
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return existing, False

        threat = Threat(
            title=threat_data["title"],
            description=threat_data.get("description", ""),
            threat_type=threat_data.get("threat_type", "unknown"),
            source=threat_data.get("source", "rule"),
            zone=threat_data.get("zone"),
            trust_boundary=boundary,
            confidence=threat_data.get("confidence", 0.5),
            rationale=threat_data.get("description", ""),
            c4_level=threat_data.get("c4_level", "system_context"),
            stride_category_detail=threat_data.get("stride_category_detail"),
        )
        self.db.add(threat)
        await self.db.flush()
        return threat, True

    async def generate_for_review(
        self, asset_id: str | None = None, zone: str | None = None
    ) -> dict:
        """Generate threat candidates WITHOUT saving to DB. Returns grouped by confidence tier."""
        logger.info("Generating threats for review", asset_id=asset_id, zone=zone)

        # Get target assets
        if asset_id:
            result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            assets = [asset] if asset else []
        elif zone:
            result = await self.db.execute(select(Asset).where(Asset.zone == zone))
            assets = list(result.scalars().all())
        else:
            result = await self.db.execute(select(Asset))
            assets = list(result.scalars().all())

        if not assets:
            logger.info("No assets found for threat evaluation", asset_id=asset_id, zone=zone)
            return {
                "high": [], "medium": [], "low": [],
                "total_candidates": 0, "total_assets": 0, "duplicates": 0,
            }

        candidates = []

        for asset in assets:
            try:
                threats = self._generate_threats_for_asset(asset)
                for threat_data in threats:
                    confidence = self._score_confidence(asset, threat_data)

                    # Check for duplicates
                    dup_result = await self.db.execute(
                        select(Threat).where(
                            Threat.asset_id == asset.id,
                            Threat.title == threat_data["title"],
                        )
                    )
                    is_duplicate = dup_result.scalar_one_or_none() is not None

                    candidates.append({
                        "title": threat_data["title"],
                        "description": threat_data.get("description", ""),
                        "threat_type": threat_data.get("threat_type", "unknown"),
                        "source": threat_data.get("source", "rule"),
                        "zone": threat_data.get("zone", asset.zone),
                        "trust_boundary": threat_data.get("trust_boundary"),
                        "confidence": confidence,
                        "c4_level": threat_data.get("c4_level"),
                        "stride_category_detail": threat_data.get("stride_category_detail"),
                        "asset_id": asset.id,
                        "asset_ip": asset.ip_address,
                        "asset_hostname": asset.hostname,
                        "is_duplicate": is_duplicate,
                    })
            except Exception as e:
                logger.error("Threat evaluation failed for asset", ip=asset.ip_address, error=str(e))

        # Group by confidence tier
        high = [c for c in candidates if c["confidence"] >= 0.7]
        medium = [c for c in candidates if 0.4 <= c["confidence"] < 0.7]
        low = [c for c in candidates if c["confidence"] < 0.4]

        # Sort within tiers by confidence desc
        high.sort(key=lambda x: x["confidence"], reverse=True)
        medium.sort(key=lambda x: x["confidence"], reverse=True)
        low.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "high": high,
            "medium": medium,
            "low": low,
            "total_candidates": len(candidates),
            "total_assets": len(assets),
            "duplicates": sum(1 for c in candidates if c["is_duplicate"]),
        }

    async def accept_batch(self, threats_to_accept: list[dict]) -> dict:
        """Accept reviewed threat candidates and save to DB."""
        created = 0
        skipped = 0

        for threat_data in threats_to_accept:
            asset_id = threat_data.get("asset_id")
            if not asset_id:
                skipped += 1
                continue

            # Check duplicate
            result = await self.db.execute(
                select(Threat).where(
                    Threat.asset_id == asset_id,
                    Threat.title == threat_data["title"],
                )
            )
            if result.scalar_one_or_none():
                skipped += 1
                continue

            threat = Threat(
                asset_id=asset_id,
                title=threat_data["title"],
                description=threat_data.get("description", ""),
                threat_type=threat_data.get("threat_type", "unknown"),
                source=threat_data.get("source", "rule"),
                zone=threat_data.get("zone"),
                trust_boundary=threat_data.get("trust_boundary"),
                confidence=threat_data.get("confidence", 0.5),
                rationale=threat_data.get("description", ""),
                c4_level=threat_data.get("c4_level"),
                stride_category_detail=threat_data.get("stride_category_detail"),
            )
            self.db.add(threat)
            created += 1

        await self.db.flush()

        await self.audit_trail.log(
            event_type="threat_batch_accept",
            entity_type="threat",
            entity_id="batch",
            actor="user",
            action="accept_batch",
            new_value={"created": created, "skipped": skipped},
        )

        return {"status": "completed", "created": created, "skipped": skipped}

    async def run_zone_threat_analysis(
        self, zone: str, run_id: str | None = None
    ) -> dict:
        """Run zone-level threat analysis."""
        try:
            from mcp_servers.threat_modeling.rules import ThreatRuleEngine
        except ImportError:
            import sys, os
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
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
                    c4_level=threat_data.get("c4_level", "container"),
                    stride_category_detail=threat_data.get("stride_category_detail"),
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
