"""Reporting MCP Server.

Provides five tools for generating reports from risk assessment data:
    - generate_html_report: Full HTML report from run data
    - generate_pdf_report: PDF report (base64 encoded), falls back to HTML
    - export_json: Structured JSON export of risk register / findings
    - export_csv: CSV export of findings
    - generate_executive_summary: Concise management summary
"""

import asyncio
import csv
import io
import json
from datetime import datetime

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.reporting.html_report import HTMLReportGenerator
from mcp_servers.reporting.pdf_report import PDFReportGenerator

logger = structlog.get_logger()

server = BaseMCPServer(name="reporting", version="1.0.0")
html_generator = HTMLReportGenerator()
pdf_generator = PDFReportGenerator()


# ======================================================================
# Tool 1: generate_html_report
# ======================================================================

@server.tool(
    name="generate_html_report",
    description=(
        "Generate a complete standalone HTML report from risk assessment run "
        "data. The report includes an executive summary, asset inventory, "
        "findings grouped by severity, risk register, MITRE ATT&CK coverage, "
        "and audit trail. Returns the full HTML string."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "assets": {
                "type": "array",
                "description": "List of asset dicts (ip_address, hostname, asset_type, zone, criticality, os_guess, open_ports)",
                "items": {"type": "object"},
            },
            "findings": {
                "type": "array",
                "description": "List of finding dicts (title, description, severity, category, source_tool, source_check, cve_ids, evidence, remediation)",
                "items": {"type": "object"},
            },
            "risks": {
                "type": "array",
                "description": "List of risk analysis dicts (asset_ip, scenario, risk_level, likelihood, impact, recommended_treatment)",
                "items": {"type": "object"},
            },
            "mitre_mappings": {
                "type": "array",
                "description": "List of MITRE ATT&CK mapping dicts (technique_id, technique_name, tactics, confidence, finding_title)",
                "items": {"type": "object"},
            },
            "metadata": {
                "type": "object",
                "description": "Run metadata (run_id, timestamp, scope, initiated_by, etc.)",
            },
        },
        "required": [],
    },
)
async def generate_html_report(
    assets: list[dict] | None = None,
    findings: list[dict] | None = None,
    risks: list[dict] | None = None,
    mitre_mappings: list[dict] | None = None,
    metadata: dict | None = None,
) -> dict:
    """Generate a complete HTML report and return it as a string."""
    logger.info(
        "generate_html_report called",
        assets=len(assets or []),
        findings=len(findings or []),
        risks=len(risks or []),
    )

    data = {
        "assets": assets or [],
        "findings": findings or [],
        "risks": risks or [],
        "mitre_mappings": mitre_mappings or [],
        "metadata": metadata or {},
    }

    html_content = html_generator.generate(data)

    return ToolResult(
        success=True,
        data={"html": html_content, "length": len(html_content)},
        artifacts=[{
            "type": "report",
            "format": "html",
            "tool": "reporting",
            "content": html_content,
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "report_type": "html",
            "assets_count": len(assets or []),
            "findings_count": len(findings or []),
            "risks_count": len(risks or []),
        },
    ).model_dump()


# ======================================================================
# Tool 2: generate_pdf_report
# ======================================================================

@server.tool(
    name="generate_pdf_report",
    description=(
        "Generate a PDF report from risk assessment run data. The PDF content "
        "is returned as a base64-encoded string. If weasyprint is not "
        "available, falls back to returning base64-encoded HTML. Also returns "
        "the format (pdf or html) so the caller knows what was generated."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "assets": {
                "type": "array",
                "description": "List of asset dicts",
                "items": {"type": "object"},
            },
            "findings": {
                "type": "array",
                "description": "List of finding dicts",
                "items": {"type": "object"},
            },
            "risks": {
                "type": "array",
                "description": "List of risk analysis dicts",
                "items": {"type": "object"},
            },
            "mitre_mappings": {
                "type": "array",
                "description": "List of MITRE ATT&CK mapping dicts",
                "items": {"type": "object"},
            },
            "metadata": {
                "type": "object",
                "description": "Run metadata",
            },
            "output_path": {
                "type": "string",
                "description": "Optional filesystem path to write the PDF. If omitted, only base64 content is returned.",
            },
        },
        "required": [],
    },
)
async def generate_pdf_report(
    assets: list[dict] | None = None,
    findings: list[dict] | None = None,
    risks: list[dict] | None = None,
    mitre_mappings: list[dict] | None = None,
    metadata: dict | None = None,
    output_path: str | None = None,
) -> dict:
    """Generate a PDF report; return base64-encoded content and optional file path."""
    logger.info(
        "generate_pdf_report called",
        assets=len(assets or []),
        findings=len(findings or []),
        output_path=output_path,
    )

    data = {
        "assets": assets or [],
        "findings": findings or [],
        "risks": risks or [],
        "mitre_mappings": mitre_mappings or [],
        "metadata": metadata or {},
    }

    base64_content, fmt = pdf_generator.generate_base64(data)

    result_data: dict = {
        "base64_content": base64_content,
        "format": fmt,
    }

    # Optionally write to disk
    file_path = None
    if output_path:
        file_path = pdf_generator.generate(data, output_path)
        result_data["file_path"] = file_path

    return ToolResult(
        success=True,
        data=result_data,
        artifacts=[{
            "type": "report",
            "format": fmt,
            "tool": "reporting",
            "timestamp": datetime.utcnow().isoformat(),
            "file_path": file_path,
        }],
        metadata={
            "report_type": fmt,
            "file_path": file_path,
            "content_length": len(base64_content),
        },
    ).model_dump()


# ======================================================================
# Tool 3: export_json
# ======================================================================

@server.tool(
    name="export_json",
    description=(
        "Export risk register and/or findings as structured JSON. Returns a "
        "JSON string with the selected data sections, suitable for ingestion "
        "by other tools or dashboards."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of finding dicts to include",
                "items": {"type": "object"},
            },
            "risks": {
                "type": "array",
                "description": "List of risk register entries to include",
                "items": {"type": "object"},
            },
            "assets": {
                "type": "array",
                "description": "Optional list of asset dicts",
                "items": {"type": "object"},
            },
            "metadata": {
                "type": "object",
                "description": "Optional run metadata to embed in the export",
            },
            "include_sections": {
                "type": "array",
                "description": "Sections to include: 'findings', 'risks', 'assets', 'metadata'. Defaults to all provided.",
                "items": {"type": "string"},
            },
        },
        "required": [],
    },
)
async def export_json(
    findings: list[dict] | None = None,
    risks: list[dict] | None = None,
    assets: list[dict] | None = None,
    metadata: dict | None = None,
    include_sections: list[str] | None = None,
) -> dict:
    """Export risk register / findings as structured JSON."""
    logger.info(
        "export_json called",
        findings=len(findings or []),
        risks=len(risks or []),
        include_sections=include_sections,
    )

    sections = include_sections or []
    include_all = len(sections) == 0  # if nothing specified, include everything provided

    export: dict = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "export_format": "json",
    }

    if (include_all or "metadata" in sections) and metadata:
        export["metadata"] = metadata
    if (include_all or "assets" in sections) and assets is not None:
        export["assets"] = assets
    if (include_all or "findings" in sections) and findings is not None:
        export["findings"] = findings
        # Add summary stats
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        export["findings_summary"] = {
            "total": len(findings),
            "by_severity": sev_counts,
        }
    if (include_all or "risks" in sections) and risks is not None:
        export["risks"] = risks
        risk_counts: dict[str, int] = {}
        for r in risks:
            lvl = (r.get("risk_level") or "low").lower()
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
        export["risks_summary"] = {
            "total": len(risks),
            "by_risk_level": risk_counts,
        }

    json_str = json.dumps(export, indent=2, default=str)

    return ToolResult(
        success=True,
        data={"json": json_str, "length": len(json_str)},
        artifacts=[{
            "type": "export",
            "format": "json",
            "tool": "reporting",
            "content": json_str,
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "export_format": "json",
            "sections": list(export.keys()),
        },
    ).model_dump()


# ======================================================================
# Tool 4: export_csv
# ======================================================================

@server.tool(
    name="export_csv",
    description=(
        "Export findings as a CSV string. Each row represents one finding "
        "with columns: title, description, severity, category, source_tool, "
        "source_check, cve_ids, cwe_id, evidence, remediation."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of finding dicts to export as CSV rows",
                "items": {"type": "object"},
            },
        },
        "required": ["findings"],
    },
)
async def export_csv(findings: list[dict]) -> dict:
    """Export findings as a CSV string."""
    logger.info("export_csv called", findings=len(findings))

    columns = [
        "title",
        "description",
        "severity",
        "category",
        "source_tool",
        "source_check",
        "cve_ids",
        "cwe_id",
        "evidence",
        "remediation",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()

    for finding in findings:
        row = {}
        for col in columns:
            val = finding.get(col, "")
            if isinstance(val, list):
                val = "; ".join(str(v) for v in val)
            row[col] = val if val is not None else ""
        writer.writerow(row)

    csv_str = output.getvalue()

    return ToolResult(
        success=True,
        data={"csv": csv_str, "row_count": len(findings), "columns": columns},
        artifacts=[{
            "type": "export",
            "format": "csv",
            "tool": "reporting",
            "content": csv_str,
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "export_format": "csv",
            "row_count": len(findings),
            "column_count": len(columns),
        },
    ).model_dump()


# ======================================================================
# Tool 5: generate_executive_summary
# ======================================================================

@server.tool(
    name="generate_executive_summary",
    description=(
        "Generate a concise executive / management summary from aggregated "
        "risk assessment data. Returns a structured summary with overall risk "
        "posture, key metrics, top findings, recommended priorities, and "
        "a narrative paragraph suitable for management reporting."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "assets": {
                "type": "array",
                "description": "List of asset dicts",
                "items": {"type": "object"},
            },
            "findings": {
                "type": "array",
                "description": "List of finding dicts",
                "items": {"type": "object"},
            },
            "risks": {
                "type": "array",
                "description": "List of risk analysis dicts",
                "items": {"type": "object"},
            },
            "metadata": {
                "type": "object",
                "description": "Run metadata",
            },
        },
        "required": [],
    },
)
async def generate_executive_summary(
    assets: list[dict] | None = None,
    findings: list[dict] | None = None,
    risks: list[dict] | None = None,
    metadata: dict | None = None,
) -> dict:
    """Generate a concise management summary from aggregated data."""
    assets = assets or []
    findings = findings or []
    risks = risks or []
    metadata = metadata or {}

    logger.info(
        "generate_executive_summary called",
        assets=len(assets),
        findings=len(findings),
        risks=len(risks),
    )

    # ---- Severity distribution for findings ----
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # ---- Risk level distribution ----
    risk_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in risks:
        lvl = (r.get("risk_level") or "low").lower()
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    # ---- Overall risk posture ----
    if risk_counts["critical"] > 0 or sev_counts["critical"] > 0:
        overall_posture = "CRITICAL"
    elif risk_counts["high"] > 0 or sev_counts["high"] > 0:
        overall_posture = "HIGH"
    elif risk_counts["medium"] > 0 or sev_counts["medium"] > 0:
        overall_posture = "MEDIUM"
    elif len(findings) > 0 or len(risks) > 0:
        overall_posture = "LOW"
    else:
        overall_posture = "NOT ASSESSED"

    # ---- Top findings (up to 5, sorted critical first) ----
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get((f.get("severity") or "info").lower(), 99),
    )
    top_findings = []
    for f in sorted_findings[:5]:
        top_findings.append({
            "title": f.get("title", "Untitled"),
            "severity": (f.get("severity") or "info").upper(),
            "category": f.get("category", ""),
            "remediation": f.get("remediation", ""),
        })

    # ---- Recommended priorities ----
    priorities: list[str] = []
    if sev_counts["critical"] > 0:
        priorities.append(
            f"Immediately remediate {sev_counts['critical']} critical finding(s)."
        )
    if sev_counts["high"] > 0:
        priorities.append(
            f"Address {sev_counts['high']} high-severity finding(s) within the next sprint."
        )
    if risk_counts["critical"] > 0:
        priorities.append(
            f"Escalate {risk_counts['critical']} critical risk(s) to senior management."
        )
    if risk_counts["high"] > 0:
        priorities.append(
            f"Develop mitigation plans for {risk_counts['high']} high risk item(s)."
        )
    if not priorities:
        priorities.append("No critical or high-severity items require immediate action.")

    # ---- Narrative paragraph ----
    total_assets = len(assets)
    total_findings = len(findings)
    narrative = (
        f"A risk assessment was conducted covering {total_assets} asset(s), "
        f"identifying {total_findings} finding(s) across all severity levels. "
        f"The overall risk posture is assessed as {overall_posture}. "
    )
    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        narrative += (
            f"There are {sev_counts['critical']} critical and {sev_counts['high']} "
            f"high-severity findings requiring urgent attention. "
        )
    if risk_counts["critical"] > 0 or risk_counts["high"] > 0:
        narrative += (
            f"The risk register contains {risk_counts['critical']} critical and "
            f"{risk_counts['high']} high-level risks that should be prioritised "
            f"for treatment. "
        )
    narrative += (
        "Detailed findings and recommended treatments are provided in the full report."
    )

    summary = {
        "overall_posture": overall_posture,
        "total_assets": total_assets,
        "total_findings": total_findings,
        "total_risks": len(risks),
        "findings_by_severity": sev_counts,
        "risks_by_level": risk_counts,
        "top_findings": top_findings,
        "priorities": priorities,
        "narrative": narrative,
        "generated_at": datetime.utcnow().isoformat(),
        "run_id": metadata.get("run_id", "N/A"),
    }

    return ToolResult(
        success=True,
        data=summary,
        artifacts=[{
            "type": "summary",
            "format": "json",
            "tool": "reporting",
            "content": json.dumps(summary, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "overall_posture": overall_posture,
            "total_findings": total_findings,
            "total_risks": len(risks),
            "critical_items": sev_counts["critical"] + risk_counts["critical"],
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
