"""MITRE ATT&CK Mapping MCP server.

Maps findings and threats to MITRE ATT&CK techniques and exports
ATT&CK Navigator layers.
"""

import asyncio
import json
from datetime import datetime

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.mitre_mapping.mapper import MitreMapper
from mcp_servers.mitre_mapping.navigator import NavigatorExporter

logger = structlog.get_logger()

server = BaseMCPServer(name="mitre-mapping", version="1.0.0")
mapper = MitreMapper()
exporter = NavigatorExporter()


# --------------------------------------------------------------------------- #
# Tool 1: map_finding
# --------------------------------------------------------------------------- #
@server.tool(
    name="map_finding",
    description=(
        "Map a single security finding to MITRE ATT&CK techniques. Uses layered "
        "matching: exact rule matching on source_check, category-based rules, "
        "CWE-to-technique mapping, keyword heuristics on title/description, and "
        "service/port-based mapping. Returns a list of technique mappings with "
        "confidence scores."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "finding": {
                "type": "object",
                "description": (
                    "Finding dict with fields: title, description, severity "
                    "(info/low/medium/high/critical), category (vuln/misconfig/"
                    "exposure/info), source_tool, source_check, cwe_id, "
                    "services (list[str]), open_ports (list[int])"
                ),
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "source_tool": {"type": "string"},
                    "source_check": {"type": "string"},
                    "cwe_id": {"type": "string"},
                    "services": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "open_ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
            },
        },
        "required": ["finding"],
    },
)
async def map_finding(finding: dict) -> dict:
    """Map a single finding to ATT&CK techniques."""
    try:
        mappings = mapper.map_finding(finding)
        logger.info(
            "Finding mapped",
            title=finding.get("title", ""),
            mapping_count=len(mappings),
        )
        return ToolResult(
            success=True,
            data={
                "mappings": mappings,
                "finding_title": finding.get("title", ""),
                "mapping_count": len(mappings),
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "mitre_map_finding",
                "target": finding.get("title", "unknown"),
                "content": json.dumps(mappings, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "source_check": finding.get("source_check"),
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "mapping_count": len(mappings),
            },
        ).model_dump()
    except Exception as exc:
        logger.error("map_finding failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# --------------------------------------------------------------------------- #
# Tool 2: map_threat
# --------------------------------------------------------------------------- #
@server.tool(
    name="map_threat",
    description=(
        "Map a STRIDE threat to MITRE ATT&CK techniques. Takes a threat dict "
        "with threat_type (spoofing/tampering/repudiation/information_disclosure/"
        "denial_of_service/elevation_of_privilege), description, and optional "
        "services list. Returns ATT&CK technique mappings with confidence scores."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "threat": {
                "type": "object",
                "description": "Threat dict with threat_type, description, and optional services",
                "properties": {
                    "threat_type": {
                        "type": "string",
                        "description": (
                            "STRIDE category: spoofing, tampering, repudiation, "
                            "information_disclosure, denial_of_service, "
                            "elevation_of_privilege"
                        ),
                    },
                    "description": {"type": "string"},
                    "services": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Associated services (e.g. ssh, http, smb)",
                    },
                },
                "required": ["threat_type", "description"],
            },
        },
        "required": ["threat"],
    },
)
async def map_threat(threat: dict) -> dict:
    """Map a STRIDE threat to ATT&CK techniques."""
    try:
        mappings = mapper.map_threat(threat)
        logger.info(
            "Threat mapped",
            threat_type=threat.get("threat_type", ""),
            mapping_count=len(mappings),
        )
        return ToolResult(
            success=True,
            data={
                "mappings": mappings,
                "threat_type": threat.get("threat_type", ""),
                "mapping_count": len(mappings),
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "mitre_map_threat",
                "target": threat.get("threat_type", "unknown"),
                "content": json.dumps(mappings, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "threat_type": threat.get("threat_type"),
                "mapping_count": len(mappings),
            },
        ).model_dump()
    except Exception as exc:
        logger.error("map_threat failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# --------------------------------------------------------------------------- #
# Tool 3: batch_map
# --------------------------------------------------------------------------- #
@server.tool(
    name="batch_map",
    description=(
        "Map a batch of findings to MITRE ATT&CK techniques. Processes each "
        "finding and returns all mappings deduplicated by technique_id (keeping "
        "the highest confidence for each technique). Useful for generating a "
        "consolidated view across many findings."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "Finding dict (same schema as map_finding)",
                },
                "description": "List of finding dicts to map",
            },
        },
        "required": ["findings"],
    },
)
async def batch_map(findings: list[dict]) -> dict:
    """Map multiple findings and return deduplicated ATT&CK mappings."""
    try:
        all_mappings: list[dict] = []
        per_finding: list[dict] = []

        for finding in findings:
            finding_mappings = mapper.map_finding(finding)
            all_mappings.extend(finding_mappings)
            per_finding.append({
                "finding_title": finding.get("title", ""),
                "mapping_count": len(finding_mappings),
            })

        # Deduplicate: keep highest confidence per technique_id
        deduped: dict[str, dict] = {}
        for m in all_mappings:
            tech_id = m["technique_id"]
            if tech_id not in deduped or m["confidence"] > deduped[tech_id]["confidence"]:
                deduped[tech_id] = m

        unique_mappings = sorted(deduped.values(), key=lambda x: x["confidence"], reverse=True)

        logger.info(
            "Batch mapping complete",
            finding_count=len(findings),
            total_raw=len(all_mappings),
            unique_techniques=len(unique_mappings),
        )

        return ToolResult(
            success=True,
            data={
                "mappings": unique_mappings,
                "all_mappings": all_mappings,
                "summary": {
                    "findings_processed": len(findings),
                    "total_raw_mappings": len(all_mappings),
                    "unique_techniques": len(unique_mappings),
                },
                "per_finding": per_finding,
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "mitre_batch_map",
                "target": f"{len(findings)}_findings",
                "content": json.dumps(unique_mappings, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "findings_processed": len(findings),
                "unique_techniques": len(unique_mappings),
            },
        ).model_dump()
    except Exception as exc:
        logger.error("batch_map failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# --------------------------------------------------------------------------- #
# Tool 4: export_navigator_layer
# --------------------------------------------------------------------------- #
@server.tool(
    name="export_navigator_layer",
    description=(
        "Export a list of ATT&CK technique mappings as a valid ATT&CK Navigator "
        "v4.x layer JSON. The layer can be imported directly into the MITRE "
        "ATT&CK Navigator for visualisation. Aggregates duplicate techniques by "
        "taking the max confidence score."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "mappings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "Mapping dict with technique_id, technique_name, tactic, confidence, source, rationale",
                },
                "description": "List of ATT&CK technique mappings (output of map_finding / batch_map)",
            },
            "layer_name": {
                "type": "string",
                "description": "Name for the Navigator layer",
                "default": "Risk Platform Findings",
            },
        },
        "required": ["mappings"],
    },
)
async def export_navigator_layer(
    mappings: list[dict],
    layer_name: str = "Risk Platform Findings",
) -> dict:
    """Export mappings as an ATT&CK Navigator layer."""
    try:
        layer = exporter.export_layer(mappings, layer_name=layer_name)

        logger.info(
            "Navigator layer exported",
            layer_name=layer_name,
            technique_count=len(layer.get("techniques", [])),
        )

        return ToolResult(
            success=True,
            data={"layer": layer},
            artifacts=[{
                "type": "navigator_layer",
                "tool": "mitre_export_navigator",
                "target": layer_name,
                "content": json.dumps(layer, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "layer_name": layer_name,
                "technique_count": len(layer.get("techniques", [])),
                "domain": layer.get("domain"),
            },
        ).model_dump()
    except Exception as exc:
        logger.error("export_navigator_layer failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
