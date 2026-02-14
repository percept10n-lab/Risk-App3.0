"""Drift Detector - core change detection logic.

Compares current network state against baseline snapshots to identify:
    1. New and removed assets
    2. Port and service changes per asset
    3. Zone migrations
    4. New exposure indicators
    5. Structured alerts with severity classification
    6. Aggregate drift scoring (0-100)
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Admin / high-risk ports that warrant elevated alert severity
# ---------------------------------------------------------------------------
ADMIN_PORTS: set[int] = {22, 23, 3389, 8080, 8443, 445, 5900, 5985, 5986}

# Zones considered higher risk for new asset alerts
HIGH_RISK_ZONES: set[str] = {"iot", "guest"}


def _now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _make_alert_id() -> str:
    """Generate a unique alert identifier."""
    return f"DRIFT-{uuid.uuid4().hex[:12].upper()}"


class DriftDetector:
    """Detects changes between network scan runs by comparing against baselines.

    All public methods are pure functions: they take data in and return data
    out with no side-effects, making them easy to test and compose.
    """

    # ==================================================================
    # Baseline creation
    # ==================================================================

    def create_baseline(self, assets: list[dict]) -> dict:
        """Create a baseline snapshot from a list of asset dicts.

        Each asset dict is expected to contain at least an ``ip`` or
        ``ip_address`` key.  Optional keys: mac, mac_address, hostname,
        asset_type / type, zone, open_ports / ports, services, exposure.

        Returns:
            Baseline dict with timestamp, asset_count, assets (keyed by IP),
            zones summary, total_open_ports, and an integrity hash.
        """
        logger.info("Creating baseline", asset_count=len(assets))

        baseline_assets: dict[str, dict] = {}
        zone_summary: dict[str, int] = {}
        total_open_ports = 0

        for asset in assets:
            ip = asset.get("ip") or asset.get("ip_address", "unknown")
            mac = asset.get("mac") or asset.get("mac_address")
            hostname = asset.get("hostname")
            asset_type = asset.get("type") or asset.get("asset_type", "unknown")
            zone = asset.get("zone", "lan")
            ports = asset.get("ports") or asset.get("open_ports", [])
            services = asset.get("services", [])
            exposure = asset.get("exposure", {})

            baseline_assets[ip] = {
                "mac": mac,
                "hostname": hostname,
                "type": asset_type,
                "zone": zone,
                "ports": sorted(ports),
                "services": services,
                "exposure": exposure,
            }

            zone_summary[zone] = zone_summary.get(zone, 0) + 1
            total_open_ports += len(ports)

        timestamp = _now_iso()

        baseline = {
            "timestamp": timestamp,
            "asset_count": len(baseline_assets),
            "assets": baseline_assets,
            "zones": zone_summary,
            "total_open_ports": total_open_ports,
        }

        # Integrity hash over the deterministic JSON representation
        canonical = json.dumps(baseline, sort_keys=True, default=str)
        baseline["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        logger.info(
            "Baseline created",
            asset_count=baseline["asset_count"],
            zones=zone_summary,
            total_open_ports=total_open_ports,
            hash=baseline["hash"],
        )
        return baseline

    # ==================================================================
    # Full comparison
    # ==================================================================

    def compare(self, current: list[dict], baseline: dict) -> dict:
        """Compare current asset list against a baseline snapshot.

        Returns a changes dict containing new_assets, removed_assets,
        changed_assets, new_ports, closed_ports, new_exposures,
        zone_changes, and a summary with total_changes, risk_score,
        and severity.
        """
        logger.info(
            "Comparing current state against baseline",
            current_count=len(current),
            baseline_count=baseline.get("asset_count", 0),
        )

        baseline_assets = baseline.get("assets", {})

        # Build current lookup keyed by IP
        current_map: dict[str, dict] = {}
        for asset in current:
            ip = asset.get("ip") or asset.get("ip_address", "unknown")
            mac = asset.get("mac") or asset.get("mac_address")
            hostname = asset.get("hostname")
            asset_type = asset.get("type") or asset.get("asset_type", "unknown")
            zone = asset.get("zone", "lan")
            ports = asset.get("ports") or asset.get("open_ports", [])
            services = asset.get("services", [])
            exposure = asset.get("exposure", {})

            current_map[ip] = {
                "mac": mac,
                "hostname": hostname,
                "type": asset_type,
                "zone": zone,
                "ports": sorted(ports),
                "services": services,
                "exposure": exposure,
            }

        current_ips = set(current_map.keys())
        baseline_ips = set(baseline_assets.keys())

        # --- New and removed assets ---
        new_asset_ips = sorted(current_ips - baseline_ips)
        removed_asset_ips = sorted(baseline_ips - current_ips)

        # --- Per-asset change detection for assets present in both ---
        changed_assets: list[dict] = []
        new_ports: list[dict] = []
        closed_ports: list[dict] = []
        new_exposures: list[dict] = []
        zone_changes: list[dict] = []

        common_ips = current_ips & baseline_ips
        for ip in sorted(common_ips):
            cur = current_map[ip]
            base = baseline_assets[ip]
            asset_changes: list[str] = []

            # Hostname change
            if cur.get("hostname") != base.get("hostname"):
                asset_changes.append(
                    f"Hostname changed from '{base.get('hostname')}' to '{cur.get('hostname')}'"
                )

            # Asset type change
            if cur.get("type") != base.get("type"):
                asset_changes.append(
                    f"Asset type changed from '{base.get('type')}' to '{cur.get('type')}'"
                )

            # MAC address change (possible spoofing indicator)
            if cur.get("mac") and base.get("mac") and cur["mac"] != base["mac"]:
                asset_changes.append(
                    f"MAC address changed from '{base['mac']}' to '{cur['mac']}' "
                    f"(potential ARP spoofing or hardware replacement)"
                )

            # Zone change
            if cur.get("zone", "lan") != base.get("zone", "lan"):
                old_zone = base.get("zone", "lan")
                new_zone = cur.get("zone", "lan")
                asset_changes.append(
                    f"Zone changed from '{old_zone}' to '{new_zone}'"
                )
                zone_changes.append({
                    "ip": ip,
                    "old_zone": old_zone,
                    "new_zone": new_zone,
                })

            # Port changes
            cur_ports = set(cur.get("ports", []))
            base_ports = set(base.get("ports", []))

            opened = sorted(cur_ports - base_ports)
            closed = sorted(base_ports - cur_ports)

            # Build service lookup for current and baseline
            cur_svc_map = self._build_service_map(cur.get("services", []))
            base_svc_map = self._build_service_map(base.get("services", []))

            for port in opened:
                service = cur_svc_map.get(port, "unknown")
                asset_changes.append(f"New open port {port} ({service})")
                new_ports.append({"ip": ip, "port": port, "service": service})

            for port in closed:
                service = base_svc_map.get(port, "unknown")
                asset_changes.append(f"Port {port} ({service}) is no longer open")
                closed_ports.append({"ip": ip, "port": port, "service": service})

            # Service changes on existing ports (e.g., version upgrade, service swap)
            for port in sorted(cur_ports & base_ports):
                cur_svc = cur_svc_map.get(port)
                base_svc = base_svc_map.get(port)
                if cur_svc and base_svc and cur_svc != base_svc:
                    asset_changes.append(
                        f"Service on port {port} changed from '{base_svc}' to '{cur_svc}'"
                    )

            # Exposure changes
            cur_exposure = cur.get("exposure", {})
            base_exposure = base.get("exposure", {})
            for key in sorted(set(cur_exposure.keys()) | set(base_exposure.keys())):
                cur_val = cur_exposure.get(key)
                base_val = base_exposure.get(key)
                if cur_val != base_val:
                    # New exposure indicator (was absent or False, now present/True)
                    if cur_val and not base_val:
                        asset_changes.append(
                            f"New exposure indicator: {key} = {cur_val}"
                        )
                        new_exposures.append({"ip": ip, "exposure_type": key})
                    elif base_val and not cur_val:
                        asset_changes.append(
                            f"Exposure indicator removed: {key} (was {base_val})"
                        )
                    else:
                        asset_changes.append(
                            f"Exposure indicator '{key}' changed from '{base_val}' to '{cur_val}'"
                        )

            if asset_changes:
                changed_assets.append({"ip": ip, "changes": asset_changes})

        # --- Summary ---
        total_changes = (
            len(new_asset_ips)
            + len(removed_asset_ips)
            + len(changed_assets)
            + len(new_ports)
            + len(closed_ports)
            + len(new_exposures)
            + len(zone_changes)
        )

        changes = {
            "new_assets": new_asset_ips,
            "removed_assets": removed_asset_ips,
            "changed_assets": changed_assets,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "new_exposures": new_exposures,
            "zone_changes": zone_changes,
        }

        risk_score = self.calculate_drift_score(changes, current_map)

        if risk_score >= 70:
            severity = "critical"
        elif risk_score >= 40:
            severity = "high"
        elif risk_score >= 20:
            severity = "medium"
        else:
            severity = "low"

        changes["summary"] = {
            "total_changes": total_changes,
            "risk_score": risk_score,
            "severity": severity,
        }

        logger.info(
            "Comparison complete",
            new_assets=len(new_asset_ips),
            removed_assets=len(removed_asset_ips),
            changed_assets=len(changed_assets),
            new_ports=len(new_ports),
            closed_ports=len(closed_ports),
            total_changes=total_changes,
            risk_score=risk_score,
            severity=severity,
        )
        return changes

    # ==================================================================
    # Alert generation
    # ==================================================================

    def generate_alerts(self, changes: dict, current_assets: dict | None = None) -> list[dict]:
        """Convert a changes dict into structured, actionable alerts.

        Args:
            changes: Output from :meth:`compare`.
            current_assets: Optional dict keyed by IP with asset details
                (used to determine zone context for new assets).

        Returns:
            List of alert dicts, each containing id, type, severity, title,
            description, affected_asset, recommended_action, and timestamp.
        """
        logger.info("Generating alerts from changes")

        alerts: list[dict] = []
        current_assets = current_assets or {}
        timestamp = _now_iso()

        # --- New assets ---
        for ip in changes.get("new_assets", []):
            asset_info = current_assets.get(ip, {})
            zone = asset_info.get("zone", "lan").lower()
            exposure = asset_info.get("exposure", {})
            wan_accessible = exposure.get("wan_accessible", False)

            if wan_accessible:
                severity = "critical"
                title = f"New WAN-exposed asset detected: {ip}"
                description = (
                    f"A new asset at {ip} has appeared on the network and is "
                    f"directly accessible from the WAN. This poses an immediate "
                    f"risk and requires urgent investigation."
                )
                action = (
                    "Immediately verify whether this asset is authorized. "
                    "If unauthorized, isolate it from the network. If authorized, "
                    "ensure firewall rules restrict WAN access to required ports only "
                    "and apply all security hardening measures before production use."
                )
            elif zone in HIGH_RISK_ZONES:
                severity = "high"
                title = f"New asset in {zone} zone detected: {ip}"
                description = (
                    f"A new asset at {ip} has appeared in the '{zone}' zone. "
                    f"Assets in this zone may have limited security controls "
                    f"and could serve as a pivot point for lateral movement."
                )
                action = (
                    f"Verify the asset is authorized for the '{zone}' zone. "
                    f"Ensure network segmentation isolates it from sensitive "
                    f"LAN resources. Apply appropriate access controls."
                )
            else:
                severity = "low"
                title = f"New asset detected on LAN: {ip}"
                description = (
                    f"A new asset at {ip} has appeared in the '{zone}' zone. "
                    f"This may be a new device or a previously offline system."
                )
                action = (
                    "Verify the asset is an authorized device. Update the "
                    "asset inventory and ensure it meets organizational "
                    "security policies."
                )

            alerts.append({
                "id": _make_alert_id(),
                "type": "new_asset",
                "severity": severity,
                "title": title,
                "description": description,
                "affected_asset": ip,
                "recommended_action": action,
                "timestamp": timestamp,
            })

        # --- Removed assets ---
        for ip in changes.get("removed_assets", []):
            alerts.append({
                "id": _make_alert_id(),
                "type": "removed_asset",
                "severity": "info",
                "title": f"Asset no longer detected: {ip}",
                "description": (
                    f"The asset at {ip} was present in the baseline but is "
                    f"no longer detected. This could indicate the device was "
                    f"decommissioned, powered off, or moved to a different segment."
                ),
                "affected_asset": ip,
                "recommended_action": (
                    "Confirm whether the asset was intentionally removed. "
                    "If unexpected, investigate possible device failure "
                    "or unauthorized physical removal."
                ),
                "timestamp": timestamp,
            })

        # --- New ports ---
        for entry in changes.get("new_ports", []):
            ip = entry["ip"]
            port = entry["port"]
            service = entry.get("service", "unknown")

            if port in ADMIN_PORTS:
                severity = "high"
                title = f"Administrative port {port} ({service}) opened on {ip}"
                description = (
                    f"Port {port} ({service}) is now open on {ip}. This is an "
                    f"administrative / management port commonly targeted by attackers."
                )
                action = (
                    f"Verify that port {port} ({service}) is required on {ip}. "
                    f"If needed, restrict access to authorized management IPs "
                    f"only via firewall rules. Enable strong authentication "
                    f"and audit logging for this service."
                )
            else:
                severity = "medium"
                title = f"New open port {port} ({service}) detected on {ip}"
                description = (
                    f"Port {port} ({service}) was not present in the baseline "
                    f"and is now open on {ip}. Each open port increases the "
                    f"attack surface."
                )
                action = (
                    f"Verify that port {port} ({service}) is required. "
                    f"Close unnecessary ports and ensure the service is "
                    f"up to date with security patches."
                )

            alerts.append({
                "id": _make_alert_id(),
                "type": "new_port",
                "severity": severity,
                "title": title,
                "description": description,
                "affected_asset": ip,
                "recommended_action": action,
                "timestamp": timestamp,
            })

        # --- Closed ports ---
        for entry in changes.get("closed_ports", []):
            ip = entry["ip"]
            port = entry["port"]
            service = entry.get("service", "unknown")
            alerts.append({
                "id": _make_alert_id(),
                "type": "closed_port",
                "severity": "info",
                "title": f"Port {port} ({service}) closed on {ip}",
                "description": (
                    f"Port {port} ({service}) was previously open on {ip} and "
                    f"is no longer detected. This reduces the attack surface."
                ),
                "affected_asset": ip,
                "recommended_action": (
                    "No action required if the port was intentionally closed. "
                    "If the service is expected to be running, investigate "
                    "potential service failure."
                ),
                "timestamp": timestamp,
            })

        # --- New exposures ---
        for entry in changes.get("new_exposures", []):
            ip = entry["ip"]
            exposure_type = entry["exposure_type"]
            alerts.append({
                "id": _make_alert_id(),
                "type": "new_exposure",
                "severity": "medium",
                "title": f"New exposure indicator '{exposure_type}' on {ip}",
                "description": (
                    f"A new exposure indicator '{exposure_type}' has been "
                    f"detected on {ip}. This may indicate a change in the "
                    f"asset's security posture or network configuration."
                ),
                "affected_asset": ip,
                "recommended_action": (
                    f"Investigate the new '{exposure_type}' exposure on {ip}. "
                    f"Determine if this is an intended configuration change. "
                    f"If not, remediate the exposure immediately."
                ),
                "timestamp": timestamp,
            })

        # --- Zone changes ---
        for entry in changes.get("zone_changes", []):
            ip = entry["ip"]
            old_zone = entry["old_zone"]
            new_zone = entry["new_zone"]
            alerts.append({
                "id": _make_alert_id(),
                "type": "zone_change",
                "severity": "medium",
                "title": f"Asset {ip} moved from '{old_zone}' to '{new_zone}' zone",
                "description": (
                    f"The asset at {ip} was previously in the '{old_zone}' zone "
                    f"and is now detected in the '{new_zone}' zone. Zone changes "
                    f"can alter the asset's trust level and exposure profile."
                ),
                "affected_asset": ip,
                "recommended_action": (
                    f"Confirm that moving {ip} from '{old_zone}' to '{new_zone}' "
                    f"was authorized. Verify that security policies for the new "
                    f"zone are appropriate and that network segmentation rules "
                    f"have been updated accordingly."
                ),
                "timestamp": timestamp,
            })

        # Sort alerts by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        alerts.sort(key=lambda a: severity_order.get(a["severity"], 5))

        logger.info(
            "Alerts generated",
            total_alerts=len(alerts),
            critical=sum(1 for a in alerts if a["severity"] == "critical"),
            high=sum(1 for a in alerts if a["severity"] == "high"),
            medium=sum(1 for a in alerts if a["severity"] == "medium"),
            low=sum(1 for a in alerts if a["severity"] == "low"),
            info=sum(1 for a in alerts if a["severity"] == "info"),
        )
        return alerts

    # ==================================================================
    # Drift score calculation
    # ==================================================================

    def calculate_drift_score(
        self, changes: dict, current_assets: dict | None = None
    ) -> float:
        """Calculate an aggregate drift score from 0 to 100.

        Scoring weights:
            +20  per new WAN-exposed asset
            +10  per new asset (non-WAN)
            +5   per new open port
            +15  per new exposure indicator
            +3   per zone change
            -2   per removed asset (cleanup credit)

        The final score is clamped to the [0, 100] range.

        Args:
            changes: Changes dict (output from :meth:`compare`).
            current_assets: Optional dict keyed by IP with current asset details.

        Returns:
            Float drift score between 0.0 and 100.0.
        """
        current_assets = current_assets or {}
        score = 0.0

        # New assets
        for ip in changes.get("new_assets", []):
            asset_info = current_assets.get(ip, {})
            exposure = asset_info.get("exposure", {})
            if exposure.get("wan_accessible", False):
                score += 20.0
            else:
                score += 10.0

        # New open ports
        score += len(changes.get("new_ports", [])) * 5.0

        # New exposure indicators
        score += len(changes.get("new_exposures", [])) * 15.0

        # Zone changes
        score += len(changes.get("zone_changes", [])) * 3.0

        # Removed assets (cleanup credit)
        score -= len(changes.get("removed_assets", [])) * 2.0

        # Clamp to 0-100
        score = max(0.0, min(100.0, score))

        logger.debug("Drift score calculated", score=score)
        return round(score, 1)

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _build_service_map(services: list) -> dict[int, str]:
        """Build a port-to-service-name mapping from a services list.

        Handles both flat string lists (e.g., ``["ssh", "http"]``) and
        dicts with ``port`` and ``name``/``service`` keys.
        """
        svc_map: dict[int, str] = {}
        for svc in services:
            if isinstance(svc, dict):
                port = svc.get("port")
                name = svc.get("name") or svc.get("service", "unknown")
                if port is not None:
                    try:
                        svc_map[int(port)] = str(name)
                    except (ValueError, TypeError):
                        pass
        return svc_map
