"""
Database Query Tools for LLM — 8 read-only tools the model can call via tool-use.
"""

import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.threat import Threat
from app.models.mitre_mapping import MitreMapping
from app.agents.llm_backend import ToolDefinition

import structlog

logger = structlog.get_logger()


def _truncate(text: str | None, max_len: int = 500) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


# ------------------------------------------------------------------
# Tool definitions (JSON Schema for LLM)
# ------------------------------------------------------------------

COPILOT_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="search_findings",
        description="Search vulnerability findings. Filter by severity, status, category, or asset. Returns id, title, severity, status, category, cve_ids.",
        parameters={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Filter by severity level"},
                "status": {"type": "string", "enum": ["open", "in_progress", "fixed", "accepted", "verified"], "description": "Filter by status"},
                "category": {"type": "string", "description": "Filter by category (vuln, misconfig, exposure, info)"},
                "asset_id": {"type": "string", "description": "Filter by asset UUID"},
                "limit": {"type": "integer", "default": 10, "description": "Max results to return"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="search_risks",
        description="Search risk scenarios. Filter by risk level or asset. Returns scenario, risk_level, likelihood, impact, CIA impacts.",
        parameters={
            "type": "object",
            "properties": {
                "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Filter by risk level"},
                "asset_id": {"type": "string", "description": "Filter by asset UUID"},
                "limit": {"type": "integer", "default": 10, "description": "Max results to return"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="search_threats",
        description="Search threat models. Filter by C4 level, STRIDE type, or asset. Returns title, threat_type, c4_level, zone, confidence.",
        parameters={
            "type": "object",
            "properties": {
                "c4_level": {"type": "string", "enum": ["system_context", "container", "component"], "description": "Filter by C4 decomposition level"},
                "threat_type": {"type": "string", "description": "Filter by STRIDE category (spoofing, tampering, etc.)"},
                "asset_id": {"type": "string", "description": "Filter by asset UUID"},
                "limit": {"type": "integer", "default": 10, "description": "Max results to return"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="search_assets",
        description="Search network assets. Filter by zone or type. Returns hostname, IP, type, zone, criticality, vendor, OS.",
        parameters={
            "type": "object",
            "properties": {
                "zone": {"type": "string", "description": "Filter by network zone (lan, iot, dmz, guest, wan)"},
                "asset_type": {"type": "string", "description": "Filter by asset type"},
                "limit": {"type": "integer", "default": 15, "description": "Max results to return"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="get_finding_detail",
        description="Get full details for a specific finding including asset info, MITRE mappings, and associated risks.",
        parameters={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding UUID (full or partial prefix)"},
            },
            "required": ["finding_id"],
        },
    ),
    ToolDefinition(
        name="get_asset_detail",
        description="Get full details for a specific asset including its findings, threats, and risks. Can look up by ID or IP address.",
        parameters={
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "Asset UUID or IP address"},
            },
            "required": ["asset_id"],
        },
    ),
    ToolDefinition(
        name="get_security_posture",
        description="Get a dashboard summary of the overall security posture: total counts, severity breakdown, risk level breakdown.",
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    ToolDefinition(
        name="lookup_mitre_technique",
        description="Look up MITRE ATT&CK technique mappings. Optionally filter by technique ID.",
        parameters={
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "MITRE technique ID (e.g. T1190)"},
            },
            "required": [],
        },
    ),
    # --- Write tools (require user confirmation) ---
    ToolDefinition(
        name="update_finding_status",
        description="Update the status of a finding (e.g., mark as fixed, in_progress, accepted). Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding UUID"},
                "new_status": {"type": "string", "enum": ["open", "in_progress", "fixed", "accepted", "verified"], "description": "New status"},
                "rationale": {"type": "string", "description": "Reason for the status change"},
            },
            "required": ["finding_id", "new_status"],
        },
    ),
    ToolDefinition(
        name="apply_risk_treatment",
        description="Apply a treatment to a risk scenario (accept, mitigate, transfer, avoid). Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "risk_id": {"type": "string", "description": "Risk UUID"},
                "treatment": {"type": "string", "enum": ["accept", "mitigate", "transfer", "avoid"], "description": "Treatment type"},
                "rationale": {"type": "string", "description": "Reason for the treatment choice"},
            },
            "required": ["risk_id", "treatment"],
        },
    ),
    ToolDefinition(
        name="trigger_vulnerability_scan",
        description="Trigger a vulnerability scan on a specific asset or all assets. Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "Asset UUID (omit for all assets)"},
                "reason": {"type": "string", "description": "Why the scan is needed"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="run_risk_analysis",
        description="Run risk analysis (ISO 27005) on a specific asset or all assets. Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "Asset UUID (omit for all assets)"},
                "reason": {"type": "string", "description": "Why the analysis is needed"},
            },
            "required": [],
        },
    ),
    ToolDefinition(
        name="generate_report",
        description="Generate a security report. Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "report_type": {"type": "string", "enum": ["executive", "technical", "compliance", "risk"], "description": "Report type"},
                "title": {"type": "string", "description": "Report title"},
            },
            "required": ["report_type"],
        },
    ),
    ToolDefinition(
        name="create_note",
        description="Create a note/annotation on an entity (finding, asset, risk, threat). Requires user confirmation.",
        parameters={
            "type": "object",
            "properties": {
                "entity_type": {"type": "string", "enum": ["finding", "asset", "risk", "threat"], "description": "Entity type"},
                "entity_id": {"type": "string", "description": "Entity UUID"},
                "content": {"type": "string", "description": "Note content"},
            },
            "required": ["entity_type", "entity_id", "content"],
        },
    ),
]

# Write tools that need confirmation before execution
WRITE_TOOL_NAMES = {
    "update_finding_status",
    "apply_risk_treatment",
    "trigger_vulnerability_scan",
    "run_risk_analysis",
    "generate_report",
    "create_note",
}


# ------------------------------------------------------------------
# Tool Executor
# ------------------------------------------------------------------

class ToolExecutor:
    """Routes tool calls to database query methods. All queries are read-only."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute(self, name: str, args: dict) -> str:
        """Execute a tool by name. Returns JSON string."""
        method = getattr(self, f"_tool_{name}", None)
        if not method:
            return json.dumps({"error": f"Unknown tool: {name}"})
        try:
            result = await method(**args)
            return json.dumps(result, default=str)
        except Exception as e:
            logger.error("Tool execution failed", tool=name, error=str(e))
            return json.dumps({"error": f"Tool {name} failed: {e}"})

    async def _tool_search_findings(
        self,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        asset_id: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        query = select(Finding).order_by(Finding.severity.desc()).limit(min(limit, 25))
        if severity:
            query = query.where(Finding.severity == severity)
        if status:
            query = query.where(Finding.status == status)
        if category:
            query = query.where(Finding.category == category)
        if asset_id:
            query = query.where(Finding.asset_id == asset_id)

        result = await self.db.execute(query)
        findings = result.scalars().all()
        return [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "category": f.category,
                "cve_ids": f.cve_ids or [],
                "description": _truncate(f.description, 500),
                "asset_id": f.asset_id,
            }
            for f in findings
        ]

    async def _tool_search_risks(
        self,
        risk_level: str | None = None,
        asset_id: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        query = select(Risk).order_by(Risk.risk_level.desc()).limit(min(limit, 25))
        if risk_level:
            query = query.where(Risk.risk_level == risk_level)
        if asset_id:
            query = query.where(Risk.asset_id == asset_id)

        result = await self.db.execute(query)
        risks = result.scalars().all()
        return [
            {
                "id": r.id,
                "scenario": _truncate(r.scenario, 200),
                "risk_level": r.risk_level,
                "likelihood": r.likelihood,
                "impact": r.impact,
                "confidentiality_impact": r.confidentiality_impact,
                "integrity_impact": r.integrity_impact,
                "availability_impact": r.availability_impact,
                "treatment": r.treatment,
            }
            for r in risks
        ]

    async def _tool_search_threats(
        self,
        c4_level: str | None = None,
        threat_type: str | None = None,
        asset_id: str | None = None,
        limit: int = 10,
    ) -> list[dict]:
        query = select(Threat).order_by(Threat.confidence.desc()).limit(min(limit, 25))
        if c4_level:
            query = query.where(Threat.c4_level == c4_level)
        if threat_type:
            query = query.where(Threat.threat_type == threat_type)
        if asset_id:
            query = query.where(Threat.asset_id == asset_id)

        result = await self.db.execute(query)
        threats = result.scalars().all()
        return [
            {
                "id": t.id,
                "title": t.title,
                "threat_type": t.threat_type,
                "c4_level": t.c4_level,
                "zone": t.zone,
                "confidence": t.confidence,
                "trust_boundary": t.trust_boundary,
            }
            for t in threats
        ]

    async def _tool_search_assets(
        self,
        zone: str | None = None,
        asset_type: str | None = None,
        limit: int = 15,
    ) -> list[dict]:
        query = select(Asset).order_by(Asset.criticality.desc()).limit(min(limit, 30))
        if zone:
            query = query.where(Asset.zone == zone)
        if asset_type:
            query = query.where(Asset.asset_type == asset_type)

        result = await self.db.execute(query)
        assets = result.scalars().all()
        return [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "asset_type": a.asset_type,
                "zone": a.zone,
                "criticality": a.criticality,
                "vendor": a.vendor,
                "os_guess": a.os_guess,
            }
            for a in assets
        ]

    async def _tool_get_finding_detail(self, finding_id: str) -> dict:
        # Resolve partial ID
        if len(finding_id) < 36:
            result = await self.db.execute(
                select(Finding).where(Finding.id.like(f"{finding_id}%")).limit(1)
            )
        else:
            result = await self.db.execute(
                select(Finding).where(Finding.id == finding_id)
            )
        finding = result.scalar_one_or_none()
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}

        # Get asset
        asset_data = None
        if finding.asset_id:
            asset_result = await self.db.execute(
                select(Asset).where(Asset.id == finding.asset_id)
            )
            asset = asset_result.scalar_one_or_none()
            if asset:
                asset_data = {
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "zone": asset.zone,
                    "asset_type": asset.asset_type,
                    "criticality": asset.criticality,
                }

        # Get MITRE mappings
        mitre_result = await self.db.execute(
            select(MitreMapping).where(MitreMapping.finding_id == finding.id)
        )
        mitre = [
            {"technique_id": m.technique_id, "technique_name": m.technique_name, "tactic": m.tactic}
            for m in mitre_result.scalars().all()
        ]

        # Get associated risks
        risk_result = await self.db.execute(
            select(Risk).where(Risk.finding_id == finding.id).limit(5)
        )
        risks = [
            {"risk_level": r.risk_level, "scenario": _truncate(r.scenario, 200)}
            for r in risk_result.scalars().all()
        ]

        return {
            "id": finding.id,
            "title": finding.title,
            "description": _truncate(finding.description, 500),
            "severity": finding.severity,
            "status": finding.status,
            "category": finding.category,
            "cve_ids": finding.cve_ids or [],
            "remediation": _truncate(finding.remediation, 500),
            "asset": asset_data,
            "mitre_mappings": mitre,
            "risks": risks,
        }

    async def _tool_get_asset_detail(self, asset_id: str) -> dict:
        # Try by ID first, then by IP
        result = await self.db.execute(
            select(Asset).where(Asset.id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            result = await self.db.execute(
                select(Asset).where(Asset.ip_address == asset_id)
            )
            asset = result.scalar_one_or_none()
        if not asset:
            # Partial ID match
            result = await self.db.execute(
                select(Asset).where(Asset.id.like(f"{asset_id}%")).limit(1)
            )
            asset = result.scalar_one_or_none()
        if not asset:
            return {"error": f"Asset not found: {asset_id}"}

        # Get findings
        findings_result = await self.db.execute(
            select(Finding).where(Finding.asset_id == asset.id).order_by(Finding.severity.desc()).limit(10)
        )
        findings = [
            {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status}
            for f in findings_result.scalars().all()
        ]

        # Get threats
        threats_result = await self.db.execute(
            select(Threat).where(Threat.asset_id == asset.id).limit(10)
        )
        threats = [
            {"title": t.title, "threat_type": t.threat_type, "confidence": t.confidence}
            for t in threats_result.scalars().all()
        ]

        # Get risks
        risks_result = await self.db.execute(
            select(Risk).where(Risk.asset_id == asset.id).order_by(Risk.risk_level.desc()).limit(10)
        )
        risks = [
            {"risk_level": r.risk_level, "scenario": _truncate(r.scenario, 200)}
            for r in risks_result.scalars().all()
        ]

        return {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address,
            "asset_type": asset.asset_type,
            "zone": asset.zone,
            "criticality": asset.criticality,
            "vendor": asset.vendor,
            "os_guess": asset.os_guess,
            "findings": findings,
            "threats": threats,
            "risks": risks,
        }

    async def _tool_get_security_posture(self) -> dict:
        # Total counts
        total_assets = (await self.db.execute(select(func.count(Asset.id)))).scalar() or 0
        total_findings = (await self.db.execute(select(func.count(Finding.id)))).scalar() or 0
        total_risks = (await self.db.execute(select(func.count(Risk.id)))).scalar() or 0
        total_threats = (await self.db.execute(select(func.count(Threat.id)))).scalar() or 0
        open_findings = (await self.db.execute(
            select(func.count(Finding.id)).where(Finding.status == "open")
        )).scalar() or 0

        # Severity breakdown
        severity_breakdown = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = (await self.db.execute(
                select(func.count(Finding.id)).where(Finding.severity == sev)
            )).scalar() or 0
            if count > 0:
                severity_breakdown[sev] = count

        # Risk level breakdown
        risk_breakdown = {}
        for level in ["critical", "high", "medium", "low"]:
            count = (await self.db.execute(
                select(func.count(Risk.id)).where(Risk.risk_level == level)
            )).scalar() or 0
            if count > 0:
                risk_breakdown[level] = count

        return {
            "total_assets": total_assets,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "total_risks": total_risks,
            "total_threats": total_threats,
            "severity_breakdown": severity_breakdown,
            "risk_breakdown": risk_breakdown,
        }

    async def _tool_lookup_mitre_technique(self, technique_id: str | None = None) -> list[dict]:
        query = select(MitreMapping).order_by(MitreMapping.confidence.desc()).limit(20)
        if technique_id:
            query = query.where(MitreMapping.technique_id == technique_id)

        result = await self.db.execute(query)
        mappings = result.scalars().all()
        return [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "finding_id": m.finding_id,
                "rationale": _truncate(m.rationale, 200),
            }
            for m in mappings
        ]

    # --- Write tools (return pending_confirmation) ---

    async def _tool_update_finding_status(
        self, finding_id: str, new_status: str, rationale: str = ""
    ) -> dict:
        """Validate but don't mutate — return pending confirmation."""
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            # Try partial ID
            result = await self.db.execute(
                select(Finding).where(Finding.id.like(f"{finding_id}%")).limit(1)
            )
            finding = result.scalar_one_or_none()
        if not finding:
            return {"error": f"Finding not found: {finding_id}"}
        return {
            "pending_confirmation": True,
            "tool": "update_finding_status",
            "description": f"Change finding '{finding.title}' status from '{finding.status}' to '{new_status}'",
            "args": {"finding_id": finding.id, "new_status": new_status, "rationale": rationale},
        }

    async def _tool_apply_risk_treatment(
        self, risk_id: str, treatment: str, rationale: str = ""
    ) -> dict:
        result = await self.db.execute(select(Risk).where(Risk.id == risk_id))
        risk = result.scalar_one_or_none()
        if not risk:
            result = await self.db.execute(
                select(Risk).where(Risk.id.like(f"{risk_id}%")).limit(1)
            )
            risk = result.scalar_one_or_none()
        if not risk:
            return {"error": f"Risk not found: {risk_id}"}
        return {
            "pending_confirmation": True,
            "tool": "apply_risk_treatment",
            "description": f"Apply '{treatment}' treatment to risk: {_truncate(risk.scenario, 80)}",
            "args": {"risk_id": risk.id, "treatment": treatment, "rationale": rationale},
        }

    async def _tool_trigger_vulnerability_scan(
        self, asset_id: str | None = None, reason: str = ""
    ) -> dict:
        desc = f"vulnerability scan on asset {asset_id}" if asset_id else "vulnerability scan on all assets"
        return {
            "pending_confirmation": True,
            "tool": "trigger_vulnerability_scan",
            "description": f"Trigger {desc}",
            "args": {"asset_id": asset_id, "reason": reason},
        }

    async def _tool_run_risk_analysis(
        self, asset_id: str | None = None, reason: str = ""
    ) -> dict:
        desc = f"risk analysis on asset {asset_id}" if asset_id else "risk analysis on all assets"
        return {
            "pending_confirmation": True,
            "tool": "run_risk_analysis",
            "description": f"Run {desc}",
            "args": {"asset_id": asset_id, "reason": reason},
        }

    async def _tool_generate_report(
        self, report_type: str, title: str = ""
    ) -> dict:
        return {
            "pending_confirmation": True,
            "tool": "generate_report",
            "description": f"Generate {report_type} report" + (f": {title}" if title else ""),
            "args": {"report_type": report_type, "title": title},
        }

    async def _tool_create_note(
        self, entity_type: str, entity_id: str, content: str
    ) -> dict:
        return {
            "pending_confirmation": True,
            "tool": "create_note",
            "description": f"Create note on {entity_type} {entity_id[:8]}...",
            "args": {"entity_type": entity_type, "entity_id": entity_id, "content": content},
        }
