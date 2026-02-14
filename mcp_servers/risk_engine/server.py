"""ISO 27005 Risk Engine MCP Server.

Provides five tools for risk analysis:
    - analyze_risk: Full risk analysis for a single asset + threat + finding
    - batch_analyze: Batch analysis of multiple risk items, sorted by risk level
    - calculate_likelihood: Standalone likelihood calculation
    - calculate_impact: Standalone impact calculation
    - suggest_treatment: Treatment recommendation based on risk level and context
"""
import asyncio
import json
from datetime import datetime

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.risk_engine.analyzer import RiskAnalyzer
from mcp_servers.risk_engine.matrix import RiskMatrix, RISK_LEVEL_ORDER
from mcp_servers.risk_engine.treatment import TreatmentAdvisor

logger = structlog.get_logger()

server = BaseMCPServer(name="risk-engine", version="1.0.0")
matrix = RiskMatrix()
analyzer = RiskAnalyzer(matrix=matrix)
treatment_advisor = TreatmentAdvisor()


# ======================================================================
# Tool 1: analyze_risk
# ======================================================================

@server.tool(
    name="analyze_risk",
    description=(
        "Perform a full ISO 27005 risk analysis for an asset combined with "
        "an optional threat and/or finding. Returns likelihood, impact, "
        "risk_level, CIA triad breakdown, scenario description, and "
        "treatment recommendation. Every score includes a rationale."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "asset": {
                "type": "object",
                "description": "Asset data including ip_address, asset_type, zone, criticality, open_ports, services, exposure",
                "properties": {
                    "ip_address": {"type": "string"},
                    "asset_type": {"type": "string"},
                    "zone": {"type": "string"},
                    "hostname": {"type": "string"},
                    "os_guess": {"type": "string"},
                    "criticality": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "services": {"type": "array"},
                    "exposure": {"type": "object"},
                },
            },
            "threat": {
                "type": "object",
                "description": "Optional threat data (title, threat_type, confidence, description)",
                "properties": {
                    "title": {"type": "string"},
                    "threat_type": {"type": "string"},
                    "confidence": {"type": "number"},
                    "description": {"type": "string"},
                },
            },
            "finding": {
                "type": "object",
                "description": "Optional finding/vulnerability data (title, severity, category, exploitability_score, description, remediation)",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "exploitability_score": {"type": "number"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                    "source_check": {"type": "string"},
                    "cve_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "required": ["asset"],
    },
)
async def analyze_risk(
    asset: dict,
    threat: dict | None = None,
    finding: dict | None = None,
) -> dict:
    """Full ISO 27005 risk analysis."""
    logger.info(
        "analyze_risk called",
        asset_ip=asset.get("ip_address", "unknown"),
        has_threat=threat is not None,
        has_finding=finding is not None,
    )

    result = analyzer.analyze(asset, threat, finding)

    return ToolResult(
        success=True,
        data=result,
        artifacts=[{
            "type": "raw_output",
            "tool": "risk_engine",
            "target": asset.get("ip_address", "unknown"),
            "content": json.dumps(result, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "risk_level": result["risk_level"],
            "likelihood": result["likelihood"],
            "impact": result["impact"],
            "asset_type": asset.get("asset_type"),
        },
    ).model_dump()


# ======================================================================
# Tool 2: batch_analyze
# ======================================================================

@server.tool(
    name="batch_analyze",
    description=(
        "Batch ISO 27005 risk analysis for multiple items. Each item must "
        "contain an 'asset' dict and optionally 'threat' and/or 'finding'. "
        "Results are sorted by risk_level (critical first)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "description": "List of risk items, each with asset (required), threat (optional), finding (optional)",
                "items": {
                    "type": "object",
                    "properties": {
                        "asset": {"type": "object"},
                        "threat": {"type": "object"},
                        "finding": {"type": "object"},
                    },
                    "required": ["asset"],
                },
            },
        },
        "required": ["items"],
    },
)
async def batch_analyze(items: list[dict]) -> dict:
    """Batch risk analysis, returning results sorted by risk_level descending."""
    logger.info("batch_analyze called", item_count=len(items))

    results: list[dict] = []
    for idx, item in enumerate(items):
        asset = item.get("asset", {})
        threat = item.get("threat")
        finding = item.get("finding")

        try:
            analysis = analyzer.analyze(asset, threat, finding)
            analysis["_item_index"] = idx
            analysis["asset_ip"] = asset.get("ip_address", "unknown")
            analysis["asset_type"] = asset.get("asset_type", "unknown")
            results.append(analysis)
        except Exception as e:
            logger.error("Batch item analysis failed", index=idx, error=str(e))
            results.append({
                "_item_index": idx,
                "asset_ip": asset.get("ip_address", "unknown"),
                "error": str(e),
                "risk_level": "low",  # default for sorting
            })

    # Sort by risk_level descending (critical > high > medium > low)
    results.sort(
        key=lambda r: RISK_LEVEL_ORDER.get(r.get("risk_level", "low"), 0),
        reverse=True,
    )

    # Summary statistics
    level_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        level = r.get("risk_level", "low")
        level_counts[level] = level_counts.get(level, 0) + 1

    return ToolResult(
        success=True,
        data={
            "results": results,
            "summary": {
                "total": len(results),
                "by_risk_level": level_counts,
            },
        },
        artifacts=[{
            "type": "raw_output",
            "tool": "risk_engine_batch",
            "target": "batch",
            "content": json.dumps({"summary": level_counts, "count": len(results)}, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "total_items": len(results),
            "risk_distribution": level_counts,
        },
    ).model_dump()


# ======================================================================
# Tool 3: calculate_likelihood
# ======================================================================

@server.tool(
    name="calculate_likelihood",
    description=(
        "Calculate risk likelihood based on exposure level, exploitability, "
        "threat capability, and existing controls. Returns the likelihood "
        "enum value (very_low/low/medium/high/very_high) with full rationale."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "asset": {
                "type": "object",
                "description": "Asset data (zone, exposure, open_ports, services)",
                "properties": {
                    "ip_address": {"type": "string"},
                    "zone": {"type": "string"},
                    "exposure": {"type": "object"},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "services": {"type": "array"},
                },
            },
            "threat": {
                "type": "object",
                "description": "Optional threat data (confidence, threat_type)",
                "properties": {
                    "confidence": {"type": "number"},
                    "threat_type": {"type": "string"},
                },
            },
            "finding": {
                "type": "object",
                "description": "Optional finding data (exploitability_score, severity)",
                "properties": {
                    "exploitability_score": {"type": "number"},
                    "severity": {"type": "string"},
                },
            },
        },
        "required": ["asset"],
    },
)
async def calculate_likelihood(
    asset: dict,
    threat: dict | None = None,
    finding: dict | None = None,
) -> dict:
    """Standalone likelihood calculation."""
    logger.info("calculate_likelihood called", asset_ip=asset.get("ip_address", "unknown"))

    likelihood, rationale, factors = analyzer.calculate_likelihood(asset, threat, finding)

    return ToolResult(
        success=True,
        data={
            "likelihood": likelihood,
            "rationale": rationale,
            "factors": factors,
        },
        metadata={"likelihood": likelihood},
    ).model_dump()


# ======================================================================
# Tool 4: calculate_impact
# ======================================================================

@server.tool(
    name="calculate_impact",
    description=(
        "Calculate risk impact based on CIA triad analysis and asset "
        "criticality. Returns the impact enum value "
        "(negligible/low/medium/high/critical) with CIA breakdown and rationale."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "asset": {
                "type": "object",
                "description": "Asset data (asset_type, criticality, zone, open_ports, exposure)",
                "properties": {
                    "ip_address": {"type": "string"},
                    "asset_type": {"type": "string"},
                    "criticality": {"type": "string"},
                    "zone": {"type": "string"},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "exposure": {"type": "object"},
                },
            },
            "threat": {
                "type": "object",
                "description": "Optional threat data (threat_type)",
                "properties": {
                    "threat_type": {"type": "string"},
                },
            },
            "finding": {
                "type": "object",
                "description": "Optional finding data (title, description, severity, category)",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                },
            },
        },
        "required": ["asset"],
    },
)
async def calculate_impact(
    asset: dict,
    threat: dict | None = None,
    finding: dict | None = None,
) -> dict:
    """Standalone impact calculation."""
    logger.info("calculate_impact called", asset_ip=asset.get("ip_address", "unknown"))

    impact, rationale, factors, cia = analyzer.calculate_impact(asset, threat, finding)

    return ToolResult(
        success=True,
        data={
            "impact": impact,
            "rationale": rationale,
            "factors": factors,
            "cia": cia,
        },
        metadata={
            "impact": impact,
            "confidentiality": cia["confidentiality"],
            "integrity": cia["integrity"],
            "availability": cia["availability"],
        },
    ).model_dump()


# ======================================================================
# Tool 5: suggest_treatment
# ======================================================================

@server.tool(
    name="suggest_treatment",
    description=(
        "Suggest risk treatment options based on risk level and context. "
        "Returns recommended treatment (mitigate/transfer/avoid/accept), "
        "all applicable options with pros/cons, specific mitigation actions, "
        "and rationale."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "risk_level": {
                "type": "string",
                "description": "The assessed risk level",
                "enum": ["low", "medium", "high", "critical"],
            },
            "asset": {
                "type": "object",
                "description": "Asset data for context-aware recommendations",
                "properties": {
                    "ip_address": {"type": "string"},
                    "asset_type": {"type": "string"},
                    "zone": {"type": "string"},
                    "services": {"type": "array"},
                    "open_ports": {"type": "array", "items": {"type": "integer"}},
                    "exposure": {"type": "object"},
                },
            },
            "finding": {
                "type": "object",
                "description": "Optional finding for specific mitigation actions",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "remediation": {"type": "string"},
                    "source_check": {"type": "string"},
                },
            },
            "threat": {
                "type": "object",
                "description": "Optional threat for context-aware treatment",
                "properties": {
                    "title": {"type": "string"},
                    "threat_type": {"type": "string"},
                    "description": {"type": "string"},
                },
            },
        },
        "required": ["risk_level", "asset"],
    },
)
async def suggest_treatment(
    risk_level: str,
    asset: dict,
    finding: dict | None = None,
    threat: dict | None = None,
) -> dict:
    """Suggest treatment strategies for a given risk level."""
    logger.info(
        "suggest_treatment called",
        risk_level=risk_level,
        asset_ip=asset.get("ip_address", "unknown"),
    )

    result = treatment_advisor.suggest(risk_level, asset, finding, threat)

    # Also include the matrix threshold information for this risk level
    threshold = matrix.get_treatment_threshold(risk_level)
    result["threshold"] = threshold

    return ToolResult(
        success=True,
        data=result,
        metadata={
            "risk_level": risk_level,
            "recommended_treatment": result["recommended_treatment"],
            "action_count": len(result.get("mitigation_actions", [])),
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
