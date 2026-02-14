import asyncio
import json
from datetime import datetime
from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.threat_modeling.rules import ThreatRuleEngine
from mcp_servers.threat_modeling.catalogs import STRIDE_CATALOG, HOME_THREAT_CATALOG


server = BaseMCPServer(name="threat-modeling", version="1.0.0")
rule_engine = ThreatRuleEngine()


@server.tool(
    name="generate_threats",
    description="Generate threat suggestions for an asset based on its type, services, zone, and exposure. Uses rule-based STRIDE analysis.",
    input_schema={
        "type": "object",
        "properties": {
            "asset": {
                "type": "object",
                "description": "Asset data including ip_address, asset_type, zone, exposure, open_ports, services",
                "properties": {
                    "ip_address": {"type": "string"},
                    "asset_type": {"type": "string"},
                    "zone": {"type": "string"},
                    "hostname": {"type": "string"},
                    "os_guess": {"type": "string"},
                    "exposure": {"type": "object"},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "services": {"type": "array", "items": {"type": "string"}},
                    "criticality": {"type": "string"},
                },
            },
        },
        "required": ["asset"],
    },
)
async def generate_threats(asset: dict) -> dict:
    threats = rule_engine.evaluate(asset)
    return ToolResult(
        success=True,
        data={"threats": threats, "asset_ip": asset.get("ip_address", "unknown")},
        artifacts=[{
            "type": "raw_output",
            "tool": "threat_modeling",
            "target": asset.get("ip_address", "unknown"),
            "content": json.dumps(threats, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"threat_count": len(threats), "asset_type": asset.get("asset_type")},
    ).model_dump()


@server.tool(
    name="zone_threats",
    description="Generate zone-level threats based on network zone configuration and trust boundaries.",
    input_schema={
        "type": "object",
        "properties": {
            "zone": {"type": "string", "description": "Network zone (lan, iot, guest, dmz)"},
            "asset_count": {"type": "integer", "description": "Number of assets in zone"},
            "asset_types": {"type": "array", "items": {"type": "string"}, "description": "Types of assets in zone"},
            "has_isolation": {"type": "boolean", "description": "Whether zone has VLAN isolation", "default": False},
        },
        "required": ["zone"],
    },
)
async def zone_threats(zone: str, asset_count: int = 0, asset_types: list[str] | None = None, has_isolation: bool = False) -> dict:
    threats = rule_engine.evaluate_zone(zone, asset_count, asset_types or [], has_isolation)
    return ToolResult(
        success=True,
        data={"threats": threats, "zone": zone},
        artifacts=[{
            "type": "raw_output",
            "tool": "threat_modeling_zone",
            "target": f"zone:{zone}",
            "content": json.dumps(threats, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
    ).model_dump()


@server.tool(
    name="get_stride_catalog",
    description="Get the STRIDE threat catalog for reference.",
    input_schema={"type": "object", "properties": {}},
)
async def get_stride_catalog() -> dict:
    return ToolResult(
        success=True,
        data={"catalog": STRIDE_CATALOG},
    ).model_dump()


@server.tool(
    name="trust_boundary_analysis",
    description="Analyze trust boundary crossings for potential threats.",
    input_schema={
        "type": "object",
        "properties": {
            "from_zone": {"type": "string"},
            "to_zone": {"type": "string"},
            "services_crossing": {"type": "array", "items": {"type": "string"}, "description": "Services crossing the boundary"},
            "controls": {"type": "array", "items": {"type": "string"}, "description": "Security controls at boundary"},
        },
        "required": ["from_zone", "to_zone"],
    },
)
async def trust_boundary_analysis(from_zone: str, to_zone: str, services_crossing: list[str] | None = None, controls: list[str] | None = None) -> dict:
    threats = rule_engine.evaluate_trust_boundary(from_zone, to_zone, services_crossing or [], controls or [])
    return ToolResult(
        success=True,
        data={"threats": threats, "boundary": f"{from_zone} -> {to_zone}"},
        artifacts=[{
            "type": "raw_output",
            "tool": "trust_boundary_analysis",
            "target": f"{from_zone}->{to_zone}",
            "content": json.dumps(threats, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
