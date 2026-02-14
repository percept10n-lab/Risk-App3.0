import json
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.baseline import Baseline
from app.evidence.audit_trail import AuditTrail
import structlog

logger = structlog.get_logger()


class DriftService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_trail = AuditTrail(db)

    async def create_baseline(self, zone: str, baseline_type: str = "full", run_id: str | None = None) -> dict:
        """Create a baseline snapshot of the current network state for a zone."""
        # Gather current state for the zone
        assets_result = await self.db.execute(
            select(Asset).where(Asset.zone == zone)
        )
        assets = list(assets_result.scalars().all())

        if not assets:
            return {"status": "error", "error": f"No assets found in zone '{zone}'"}

        baseline_data = {}

        if baseline_type in ("full", "assets"):
            baseline_data["assets"] = [
                {
                    "ip_address": a.ip_address,
                    "mac_address": a.mac_address,
                    "hostname": a.hostname,
                    "vendor": a.vendor,
                    "os_guess": a.os_guess,
                    "asset_type": a.asset_type,
                    "criticality": a.criticality,
                }
                for a in assets
            ]

        if baseline_type in ("full", "services"):
            baseline_data["services"] = []
            for a in assets:
                exposure = a.exposure or {}
                services = exposure.get("services", [])
                open_ports = exposure.get("open_ports", [])
                baseline_data["services"].append({
                    "ip_address": a.ip_address,
                    "open_ports": open_ports,
                    "services": services,
                    "exposure": {
                        "wan": exposure.get("wan", False),
                        "upnp": exposure.get("upnp", False),
                        "admin_ui": exposure.get("admin_ui", False),
                    },
                })

        if baseline_type in ("full", "findings"):
            # Snapshot open findings for assets in this zone
            asset_ids = [a.id for a in assets]
            findings_result = await self.db.execute(
                select(Finding).where(
                    Finding.asset_id.in_(asset_ids),
                    Finding.status == "open",
                )
            )
            findings = list(findings_result.scalars().all())
            baseline_data["findings_snapshot"] = {
                "total_open": len(findings),
                "by_severity": {},
            }
            for f in findings:
                sev = f.severity
                baseline_data["findings_snapshot"]["by_severity"][sev] = (
                    baseline_data["findings_snapshot"]["by_severity"].get(sev, 0) + 1
                )

        baseline_data["created_at"] = datetime.utcnow().isoformat()
        baseline_data["asset_count"] = len(assets)

        baseline = Baseline(
            zone=zone,
            baseline_type=baseline_type,
            baseline_data=baseline_data,
            created_from_run_id=run_id,
        )
        self.db.add(baseline)
        await self.db.flush()
        await self.db.refresh(baseline)

        await self.audit_trail.log(
            event_type="action", entity_type="baseline",
            entity_id=baseline.id, actor="system",
            action="create_baseline",
            run_id=run_id,
            new_value={"zone": zone, "type": baseline_type, "asset_count": len(assets)},
        )

        return {
            "status": "created",
            "baseline_id": baseline.id,
            "zone": zone,
            "baseline_type": baseline_type,
            "asset_count": len(assets),
        }

    async def detect_changes(self, zone: str | None = None) -> dict:
        """Detect changes since the last baseline."""
        # Find the most recent baseline(s)
        query = select(Baseline).order_by(Baseline.created_at.desc())
        if zone:
            query = query.where(Baseline.zone == zone)

        result = await self.db.execute(query)
        baselines = list(result.scalars().all())

        if not baselines:
            return {
                "changes": [],
                "total": 0,
                "message": "No baseline found. Create a baseline first.",
            }

        # Group baselines by zone (latest per zone)
        latest_by_zone = {}
        for b in baselines:
            if b.zone not in latest_by_zone:
                latest_by_zone[b.zone] = b

        all_changes = []

        for zone_name, baseline in latest_by_zone.items():
            changes = await self._compare_baseline(zone_name, baseline)
            all_changes.extend(changes)

        # Sort by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        all_changes.sort(key=lambda c: severity_order.get(c.get("severity", "info"), 0), reverse=True)

        return {
            "changes": all_changes,
            "total": len(all_changes),
            "zones_checked": list(latest_by_zone.keys()),
        }

    async def _compare_baseline(self, zone: str, baseline: Baseline) -> list[dict]:
        """Compare current state against a baseline for a zone."""
        changes = []
        baseline_data = baseline.baseline_data or {}

        # Get current assets in this zone
        current_result = await self.db.execute(
            select(Asset).where(Asset.zone == zone)
        )
        current_assets = list(current_result.scalars().all())
        current_ips = {a.ip_address for a in current_assets}

        # Compare assets
        baseline_assets = baseline_data.get("assets", [])
        baseline_ips = {a["ip_address"] for a in baseline_assets}

        # New assets
        new_ips = current_ips - baseline_ips
        for ip in new_ips:
            asset = next((a for a in current_assets if a.ip_address == ip), None)
            changes.append({
                "type": "new_asset",
                "zone": zone,
                "severity": "medium",
                "description": f"New asset detected: {ip} ({asset.hostname or 'unknown'})",
                "details": {
                    "ip_address": ip,
                    "hostname": asset.hostname if asset else None,
                    "asset_type": asset.asset_type if asset else None,
                },
                "baseline_id": baseline.id,
                "detected_at": datetime.utcnow().isoformat(),
            })

        # Removed assets
        removed_ips = baseline_ips - current_ips
        for ip in removed_ips:
            changes.append({
                "type": "removed_asset",
                "zone": zone,
                "severity": "low",
                "description": f"Asset no longer detected: {ip}",
                "details": {"ip_address": ip},
                "baseline_id": baseline.id,
                "detected_at": datetime.utcnow().isoformat(),
            })

        # Compare services/ports for existing assets
        baseline_services = {s["ip_address"]: s for s in baseline_data.get("services", [])}
        for asset in current_assets:
            if asset.ip_address not in baseline_services:
                continue

            baseline_svc = baseline_services[asset.ip_address]
            current_exposure = asset.exposure or {}
            current_ports = set(current_exposure.get("open_ports", []))
            baseline_ports = set(baseline_svc.get("open_ports", []))

            # New ports
            new_ports = current_ports - baseline_ports
            if new_ports:
                changes.append({
                    "type": "new_ports",
                    "zone": zone,
                    "severity": "high",
                    "description": f"New open ports on {asset.ip_address}: {sorted(new_ports)}",
                    "details": {
                        "ip_address": asset.ip_address,
                        "new_ports": sorted(new_ports),
                        "hostname": asset.hostname,
                    },
                    "baseline_id": baseline.id,
                    "detected_at": datetime.utcnow().isoformat(),
                })

            # Closed ports
            closed_ports = baseline_ports - current_ports
            if closed_ports:
                changes.append({
                    "type": "closed_ports",
                    "zone": zone,
                    "severity": "info",
                    "description": f"Ports closed on {asset.ip_address}: {sorted(closed_ports)}",
                    "details": {
                        "ip_address": asset.ip_address,
                        "closed_ports": sorted(closed_ports),
                    },
                    "baseline_id": baseline.id,
                    "detected_at": datetime.utcnow().isoformat(),
                })

            # Exposure changes
            baseline_exposure = baseline_svc.get("exposure", {})
            for key in ("wan", "upnp", "admin_ui"):
                old_val = baseline_exposure.get(key, False)
                new_val = current_exposure.get(key, False)
                if old_val != new_val:
                    sev = "critical" if key == "wan" and new_val else "high"
                    changes.append({
                        "type": "exposure_change",
                        "zone": zone,
                        "severity": sev,
                        "description": f"Exposure change on {asset.ip_address}: {key} {old_val} → {new_val}",
                        "details": {
                            "ip_address": asset.ip_address,
                            "exposure_type": key,
                            "old_value": old_val,
                            "new_value": new_val,
                        },
                        "baseline_id": baseline.id,
                        "detected_at": datetime.utcnow().isoformat(),
                    })

        return changes

    async def get_alerts(self, zone: str | None = None) -> dict:
        """Get drift alerts (high/critical changes)."""
        result = await self.detect_changes(zone)
        alerts = [
            c for c in result.get("changes", [])
            if c.get("severity") in ("critical", "high")
        ]
        return {
            "alerts": alerts,
            "total": len(alerts),
            "zones_checked": result.get("zones_checked", []),
        }

    async def get_baseline_history(self, zone: str | None = None) -> dict:
        """Get baseline history for a zone."""
        query = select(Baseline).order_by(Baseline.created_at.desc()).limit(20)
        if zone:
            query = query.where(Baseline.zone == zone)

        result = await self.db.execute(query)
        baselines = list(result.scalars().all())

        return {
            "baselines": [
                {
                    "id": b.id,
                    "zone": b.zone,
                    "baseline_type": b.baseline_type,
                    "asset_count": (b.baseline_data or {}).get("asset_count", 0),
                    "created_at": b.created_at.isoformat() if b.created_at else None,
                    "run_id": b.created_from_run_id,
                }
                for b in baselines
            ],
            "total": len(baselines),
        }
