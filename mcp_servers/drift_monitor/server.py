"""Drift Monitor MCP Server.

Detects changes between scan runs by comparing against baselines.

Provides five tools:
    - create_baseline: Snapshot current asset state into a baseline
    - compare: Compare current state against a baseline, returning all drifts
    - detect_new_assets: Compare two asset lists and return new/removed assets
    - detect_port_changes: Compare port/service maps between runs
    - generate_alerts: Generate structured alerts from detected changes
"""
import asyncio
import json
from datetime import datetime, timezone

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.drift_monitor.detector import DriftDetector

logger = structlog.get_logger()

server = BaseMCPServer(name="drift-monitor", version="1.0.0")
detector = DriftDetector()


# ======================================================================
# Tool 1: create_baseline
# ======================================================================

@server.tool(
    name="create_baseline",
    description=(
        "Create a baseline snapshot from the current network state. Takes a "
        "list of asset dicts (each with ip/ip_address, mac, hostname, type, "
        "zone, ports/open_ports, services, exposure) and returns a baseline "
        "object with a SHA-256 integrity hash that can later be used with "
        "the compare tool to detect drift."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "assets": {
                "type": "array",
                "description": "List of asset dicts representing current network state",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address of the asset"},
                        "ip_address": {"type": "string", "description": "IP address (alternative key)"},
                        "mac": {"type": "string", "description": "MAC address"},
                        "hostname": {"type": "string", "description": "Hostname"},
                        "type": {"type": "string", "description": "Asset type (router, server, iot, etc.)"},
                        "asset_type": {"type": "string", "description": "Asset type (alternative key)"},
                        "zone": {"type": "string", "description": "Network zone (lan, wan, dmz, iot, guest)"},
                        "ports": {"type": "array", "items": {"type": "integer"}, "description": "Open ports"},
                        "open_ports": {"type": "array", "items": {"type": "integer"}, "description": "Open ports (alternative key)"},
                        "services": {"type": "array", "description": "Service details"},
                        "exposure": {"type": "object", "description": "Exposure indicators"},
                    },
                },
            },
        },
        "required": ["assets"],
    },
)
async def create_baseline(assets: list[dict]) -> dict:
    """Create a baseline snapshot from current asset state."""
    logger.info("create_baseline called", asset_count=len(assets))

    baseline = detector.create_baseline(assets)

    return ToolResult(
        success=True,
        data=baseline,
        artifacts=[{
            "type": "baseline_snapshot",
            "tool": "drift_monitor",
            "target": "network",
            "content": json.dumps(baseline, indent=2, default=str),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
        metadata={
            "asset_count": baseline["asset_count"],
            "total_open_ports": baseline["total_open_ports"],
            "zones": baseline["zones"],
            "hash": baseline["hash"],
        },
    ).model_dump()


# ======================================================================
# Tool 2: compare
# ======================================================================

@server.tool(
    name="compare",
    description=(
        "Compare the current network state against a baseline snapshot. "
        "Returns a detailed list of all changes/drifts including new assets, "
        "removed assets, changed assets with per-field diffs, new and closed "
        "ports, new exposure indicators, zone changes, and a summary with "
        "total_changes, risk_score (0-100), and severity."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "current": {
                "type": "array",
                "description": "List of asset dicts representing the current network state",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "mac": {"type": "string"},
                        "hostname": {"type": "string"},
                        "type": {"type": "string"},
                        "asset_type": {"type": "string"},
                        "zone": {"type": "string"},
                        "ports": {"type": "array", "items": {"type": "integer"}},
                        "open_ports": {"type": "array", "items": {"type": "integer"}},
                        "services": {"type": "array"},
                        "exposure": {"type": "object"},
                    },
                },
            },
            "baseline": {
                "type": "object",
                "description": "Baseline snapshot object (output from create_baseline)",
                "properties": {
                    "timestamp": {"type": "string"},
                    "asset_count": {"type": "integer"},
                    "assets": {"type": "object"},
                    "zones": {"type": "object"},
                    "total_open_ports": {"type": "integer"},
                    "hash": {"type": "string"},
                },
            },
        },
        "required": ["current", "baseline"],
    },
)
async def compare(current: list[dict], baseline: dict) -> dict:
    """Compare current state against baseline and return all drifts."""
    logger.info(
        "compare called",
        current_count=len(current),
        baseline_count=baseline.get("asset_count", 0),
    )

    changes = detector.compare(current, baseline)
    summary = changes.get("summary", {})

    return ToolResult(
        success=True,
        data=changes,
        artifacts=[{
            "type": "drift_report",
            "tool": "drift_monitor",
            "target": "network",
            "content": json.dumps(changes, indent=2, default=str),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
        metadata={
            "total_changes": summary.get("total_changes", 0),
            "risk_score": summary.get("risk_score", 0),
            "severity": summary.get("severity", "low"),
            "new_assets": len(changes.get("new_assets", [])),
            "removed_assets": len(changes.get("removed_assets", [])),
            "new_ports": len(changes.get("new_ports", [])),
            "closed_ports": len(changes.get("closed_ports", [])),
        },
    ).model_dump()


# ======================================================================
# Tool 3: detect_new_assets
# ======================================================================

@server.tool(
    name="detect_new_assets",
    description=(
        "Compare two asset lists and identify new and removed assets. "
        "Takes a 'current' list and a 'previous' list and returns the IPs "
        "that are new (present in current but not previous) and removed "
        "(present in previous but not current)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "current_assets": {
                "type": "array",
                "description": "Current asset list (each with ip or ip_address)",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                    },
                },
            },
            "previous_assets": {
                "type": "array",
                "description": "Previous asset list (each with ip or ip_address)",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                    },
                },
            },
        },
        "required": ["current_assets", "previous_assets"],
    },
)
async def detect_new_assets(
    current_assets: list[dict],
    previous_assets: list[dict],
) -> dict:
    """Compare two asset lists to find new and removed assets."""
    logger.info(
        "detect_new_assets called",
        current_count=len(current_assets),
        previous_count=len(previous_assets),
    )

    current_ips = {
        a.get("ip") or a.get("ip_address", "unknown") for a in current_assets
    }
    previous_ips = {
        a.get("ip") or a.get("ip_address", "unknown") for a in previous_assets
    }

    new_ips = sorted(current_ips - previous_ips)
    removed_ips = sorted(previous_ips - current_ips)

    # Build detail records for new assets
    current_lookup = {}
    for a in current_assets:
        ip = a.get("ip") or a.get("ip_address", "unknown")
        current_lookup[ip] = a

    new_asset_details = []
    for ip in new_ips:
        asset = current_lookup.get(ip, {})
        new_asset_details.append({
            "ip": ip,
            "hostname": asset.get("hostname"),
            "type": asset.get("type") or asset.get("asset_type", "unknown"),
            "zone": asset.get("zone", "lan"),
            "mac": asset.get("mac") or asset.get("mac_address"),
        })

    result = {
        "new_assets": new_ips,
        "new_asset_details": new_asset_details,
        "removed_assets": removed_ips,
        "new_count": len(new_ips),
        "removed_count": len(removed_ips),
        "current_total": len(current_ips),
        "previous_total": len(previous_ips),
    }

    return ToolResult(
        success=True,
        data=result,
        artifacts=[{
            "type": "asset_diff",
            "tool": "drift_monitor",
            "target": "network",
            "content": json.dumps(result, indent=2, default=str),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
        metadata={
            "new_count": len(new_ips),
            "removed_count": len(removed_ips),
        },
    ).model_dump()


# ======================================================================
# Tool 4: detect_port_changes
# ======================================================================

@server.tool(
    name="detect_port_changes",
    description=(
        "Compare port and service maps between two scan runs for one or more "
        "assets. Takes 'current_assets' and 'previous_assets' lists and "
        "returns per-asset port changes: newly opened ports, closed ports, "
        "and service changes on existing ports."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "current_assets": {
                "type": "array",
                "description": "Current asset list with port/service data",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "ports": {"type": "array", "items": {"type": "integer"}},
                        "open_ports": {"type": "array", "items": {"type": "integer"}},
                        "services": {"type": "array"},
                    },
                },
            },
            "previous_assets": {
                "type": "array",
                "description": "Previous asset list with port/service data",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "ports": {"type": "array", "items": {"type": "integer"}},
                        "open_ports": {"type": "array", "items": {"type": "integer"}},
                        "services": {"type": "array"},
                    },
                },
            },
        },
        "required": ["current_assets", "previous_assets"],
    },
)
async def detect_port_changes(
    current_assets: list[dict],
    previous_assets: list[dict],
) -> dict:
    """Compare port/service maps between two scan runs."""
    logger.info(
        "detect_port_changes called",
        current_count=len(current_assets),
        previous_count=len(previous_assets),
    )

    # Build lookups
    def _build_lookup(assets: list[dict]) -> dict[str, dict]:
        lookup: dict[str, dict] = {}
        for a in assets:
            ip = a.get("ip") or a.get("ip_address", "unknown")
            ports = set(a.get("ports") or a.get("open_ports", []))
            services = a.get("services", [])
            svc_map = DriftDetector._build_service_map(services)
            lookup[ip] = {"ports": ports, "services": svc_map}
        return lookup

    current_lookup = _build_lookup(current_assets)
    previous_lookup = _build_lookup(previous_assets)

    all_ips = sorted(set(current_lookup.keys()) | set(previous_lookup.keys()))

    per_asset_changes: list[dict] = []
    total_opened = 0
    total_closed = 0
    total_service_changes = 0

    for ip in all_ips:
        cur = current_lookup.get(ip)
        prev = previous_lookup.get(ip)

        if cur is None or prev is None:
            # Asset only in one list; skip (handled by detect_new_assets)
            continue

        cur_ports = cur["ports"]
        prev_ports = prev["ports"]
        cur_svcs = cur["services"]
        prev_svcs = prev["services"]

        opened = sorted(cur_ports - prev_ports)
        closed = sorted(prev_ports - cur_ports)
        service_changes: list[dict] = []

        # Service changes on ports present in both
        for port in sorted(cur_ports & prev_ports):
            cur_svc = cur_svcs.get(port)
            prev_svc = prev_svcs.get(port)
            if cur_svc and prev_svc and cur_svc != prev_svc:
                service_changes.append({
                    "port": port,
                    "previous_service": prev_svc,
                    "current_service": cur_svc,
                })

        if opened or closed or service_changes:
            opened_details = [
                {"port": p, "service": cur_svcs.get(p, "unknown")} for p in opened
            ]
            closed_details = [
                {"port": p, "service": prev_svcs.get(p, "unknown")} for p in closed
            ]

            per_asset_changes.append({
                "ip": ip,
                "opened_ports": opened_details,
                "closed_ports": closed_details,
                "service_changes": service_changes,
                "opened_count": len(opened),
                "closed_count": len(closed),
                "service_change_count": len(service_changes),
            })

            total_opened += len(opened)
            total_closed += len(closed)
            total_service_changes += len(service_changes)

    result = {
        "asset_changes": per_asset_changes,
        "summary": {
            "assets_with_changes": len(per_asset_changes),
            "total_opened_ports": total_opened,
            "total_closed_ports": total_closed,
            "total_service_changes": total_service_changes,
        },
    }

    return ToolResult(
        success=True,
        data=result,
        artifacts=[{
            "type": "port_diff",
            "tool": "drift_monitor",
            "target": "network",
            "content": json.dumps(result, indent=2, default=str),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
        metadata={
            "assets_with_changes": len(per_asset_changes),
            "total_opened": total_opened,
            "total_closed": total_closed,
            "total_service_changes": total_service_changes,
        },
    ).model_dump()


# ======================================================================
# Tool 5: generate_alerts
# ======================================================================

@server.tool(
    name="generate_alerts",
    description=(
        "Generate structured, severity-classified alerts from detected "
        "changes. Takes a changes dict (output from the compare tool) and "
        "optionally the current assets for zone/exposure context. Returns "
        "alerts sorted by severity (critical first), each with an id, type, "
        "severity, title, description, affected_asset, recommended_action, "
        "and timestamp."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "changes": {
                "type": "object",
                "description": "Changes dict (output from the compare tool)",
                "properties": {
                    "new_assets": {"type": "array", "items": {"type": "string"}},
                    "removed_assets": {"type": "array", "items": {"type": "string"}},
                    "changed_assets": {"type": "array"},
                    "new_ports": {"type": "array"},
                    "closed_ports": {"type": "array"},
                    "new_exposures": {"type": "array"},
                    "zone_changes": {"type": "array"},
                    "summary": {"type": "object"},
                },
            },
            "current_assets": {
                "type": "array",
                "description": "Optional current asset list for zone/exposure context",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "zone": {"type": "string"},
                        "exposure": {"type": "object"},
                    },
                },
            },
        },
        "required": ["changes"],
    },
)
async def generate_alerts(
    changes: dict,
    current_assets: list[dict] | None = None,
) -> dict:
    """Generate structured alerts from detected changes."""
    logger.info("generate_alerts called")

    # Build current assets lookup if provided
    assets_lookup: dict[str, dict] = {}
    if current_assets:
        for a in current_assets:
            ip = a.get("ip") or a.get("ip_address", "unknown")
            assets_lookup[ip] = {
                "zone": a.get("zone", "lan"),
                "exposure": a.get("exposure", {}),
                "type": a.get("type") or a.get("asset_type", "unknown"),
                "hostname": a.get("hostname"),
            }

    alerts = detector.generate_alerts(changes, assets_lookup)

    # Compute severity distribution
    severity_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for alert in alerts:
        sev = alert.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return ToolResult(
        success=True,
        data={
            "alerts": alerts,
            "summary": {
                "total_alerts": len(alerts),
                "by_severity": severity_counts,
            },
        },
        artifacts=[{
            "type": "alert_report",
            "tool": "drift_monitor",
            "target": "network",
            "content": json.dumps(alerts, indent=2, default=str),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
        metadata={
            "total_alerts": len(alerts),
            "severity_distribution": severity_counts,
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
