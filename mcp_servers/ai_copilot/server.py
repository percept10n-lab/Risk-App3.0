"""AI Defense Copilot MCP Server.

Provides AI-powered security analysis suggestions using rule-based logic.
No external LLM is required. All suggestions are propose-only and
evidence-grounded -- never presented as definitive actions.

Tools:
    - triage_findings: Prioritize a list of findings
    - suggest_remediation: Generate a remediation plan for a finding
    - suggest_mitre_mappings: Suggest MITRE ATT&CK mappings for a finding
    - generate_narrative: Generate an executive summary narrative
    - explain_risk: Explain a risk item in plain language
"""

import asyncio
import json
from datetime import datetime

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.ai_copilot.triage import TriageEngine
from mcp_servers.ai_copilot.remediation import RemediationAdvisor
from mcp_servers.ai_copilot.prompts import PromptTemplates

logger = structlog.get_logger()

server = BaseMCPServer(name="ai-copilot", version="1.0.0")
triage_engine = TriageEngine()
remediation_advisor = RemediationAdvisor()
prompt_templates = PromptTemplates()


# --------------------------------------------------------------------------- #
# MITRE ATT&CK knowledge base (rule-based, no external LLM)
# --------------------------------------------------------------------------- #

_MITRE_KEYWORD_MAP: list[dict] = [
    {
        "keywords": ["ssh", "brute force", "password spray", "credential stuffing"],
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["default credential", "default password", "factory default"],
        "technique_id": "T1078.001",
        "technique_name": "Valid Accounts: Default Accounts",
        "tactic": "Initial Access",
    },
    {
        "keywords": ["phishing", "spear phishing", "email attack"],
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
    },
    {
        "keywords": ["sql injection", "sqli", "database injection"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    {
        "keywords": [
            "remote code execution", "rce", "command injection",
            "code execution", "code injection",
        ],
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    {
        "keywords": ["privilege escalation", "local privilege", "suid", "sudo"],
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    {
        "keywords": ["lateral movement", "pass the hash", "pth", "psexec"],
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
    },
    {
        "keywords": ["dns exfil", "data exfiltration", "dns tunnel", "covert channel"],
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
    },
    {
        "keywords": [
            "web shell", "webshell", "backdoor", "reverse shell",
            "bind shell",
        ],
        "technique_id": "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
    },
    {
        "keywords": ["snmp", "community string", "snmp enumeration"],
        "technique_id": "T1602",
        "technique_name": "Data from Configuration Repository",
        "tactic": "Collection",
    },
    {
        "keywords": ["directory traversal", "path traversal", "lfi", "file inclusion"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
    },
    {
        "keywords": ["dns zone transfer", "axfr", "dns enumeration"],
        "technique_id": "T1590.002",
        "technique_name": "Gather Victim Network Information: DNS",
        "tactic": "Reconnaissance",
    },
    {
        "keywords": ["tls", "ssl", "certificate", "weak cipher", "encryption"],
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["ftp", "telnet", "cleartext", "unencrypted protocol"],
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["denial of service", "dos", "ddos", "resource exhaustion"],
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
    },
    {
        "keywords": ["upnp", "ssdp", "universal plug and play"],
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["exposed admin", "admin panel", "management interface"],
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
        "tactic": "Initial Access",
    },
    {
        "keywords": [
            "information disclosure", "version disclosure",
            "server banner", "directory listing",
        ],
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
    },
    {
        "keywords": ["cors", "cross-origin", "ssrf", "server-side request"],
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    {
        "keywords": ["open database", "database exposed", "mongodb", "redis", "elasticsearch"],
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic": "Collection",
    },
]


def _suggest_mitre(finding: dict) -> list[dict]:
    """Rule-based MITRE ATT&CK mapping suggestions."""
    search_text = (
        finding.get("title", "")
        + " "
        + finding.get("description", "")
        + " "
        + finding.get("source_check", "")
        + " "
        + finding.get("category", "")
    ).lower()

    suggestions: list[dict] = []
    seen_techniques: set[str] = set()

    for entry in _MITRE_KEYWORD_MAP:
        matched_keywords = [kw for kw in entry["keywords"] if kw in search_text]
        if matched_keywords:
            tech_id = entry["technique_id"]
            if tech_id in seen_techniques:
                continue
            seen_techniques.add(tech_id)

            # Confidence based on number of keyword matches
            if len(matched_keywords) >= 3:
                confidence = "high"
            elif len(matched_keywords) >= 2:
                confidence = "medium"
            else:
                confidence = "low"

            suggestions.append({
                "technique_id": tech_id,
                "technique_name": entry["technique_name"],
                "tactic": entry["tactic"],
                "confidence": confidence,
                "matched_keywords": matched_keywords,
                "rationale": (
                    f"Proposed mapping based on keyword matches: "
                    f"{', '.join(matched_keywords)} found in finding data."
                ),
                "ai_label": "AI Suggestion - Proposed",
            })

    # Sort by confidence (high first)
    conf_order = {"high": 3, "medium": 2, "low": 1}
    suggestions.sort(key=lambda s: conf_order.get(s["confidence"], 0), reverse=True)

    return suggestions


# --------------------------------------------------------------------------- #
# Risk explanation helper (rule-based, no LLM)
# --------------------------------------------------------------------------- #

_SEVERITY_ANALOGIES: dict[str, str] = {
    "critical": (
        "Think of this like leaving your front door wide open with a sign "
        "inviting strangers in. An attacker could exploit this with minimal "
        "effort, potentially causing severe damage."
    ),
    "high": (
        "This is similar to having a weak lock on your door that a determined "
        "burglar could pick. It requires some effort to exploit but the "
        "potential impact is significant."
    ),
    "medium": (
        "Imagine a window that does not latch properly. While not immediately "
        "dangerous, a motivated individual could use it to gain access if "
        "they know about it."
    ),
    "low": (
        "This is like a minor crack in your fence. It is unlikely to be "
        "exploited on its own, but it contributes to a weakened overall "
        "security posture."
    ),
    "info": (
        "This is an observation about your security setup, similar to noting "
        "that your house number is visible from the street. Not directly "
        "dangerous, but useful information for someone surveying the area."
    ),
}

_SEVERITY_IMPACTS: dict[str, str] = {
    "critical": (
        "If not addressed, this could lead to full system compromise, "
        "data breach, service outage, or significant financial and "
        "reputational damage. Exploitation may already be occurring in "
        "the wild."
    ),
    "high": (
        "An attacker exploiting this could gain unauthorized access to "
        "sensitive data or systems, potentially leading to data theft, "
        "service disruption, or further compromise of the network."
    ),
    "medium": (
        "Exploitation could result in limited unauthorized access, "
        "information leakage, or partial service disruption. The impact "
        "depends on the specific context and what other findings exist."
    ),
    "low": (
        "The direct impact is limited, but this finding could be combined "
        "with other vulnerabilities to create a more serious attack chain. "
        "It also indicates areas where security hardening is possible."
    ),
    "info": (
        "This finding has no direct security impact but provides information "
        "that an attacker could use for reconnaissance or planning. "
        "Addressing it improves defense-in-depth."
    ),
}


def _explain_risk_item(risk_item: dict) -> dict:
    """Generate a plain-language risk explanation."""
    title = risk_item.get("title", "Unknown risk item")
    severity = risk_item.get("severity", "medium").lower()
    description = risk_item.get("description", "")
    risk_level = risk_item.get("risk_level", severity)
    finding_evidence = risk_item.get("evidence", description)

    analogy = _SEVERITY_ANALOGIES.get(severity, _SEVERITY_ANALOGIES["medium"])
    impact = _SEVERITY_IMPACTS.get(severity, _SEVERITY_IMPACTS["medium"])

    # Determine recommended action based on severity
    if severity == "critical":
        action = (
            "This should be addressed immediately as a top priority. "
            "Consider emergency patching or temporarily isolating the "
            "affected system until a fix is applied."
        )
    elif severity == "high":
        action = (
            "This should be scheduled for remediation within the next "
            "few days to a week. Ensure it is tracked in the vulnerability "
            "management process."
        )
    elif severity == "medium":
        action = (
            "Plan to address this in the next regular maintenance cycle "
            "or sprint. It does not require emergency action but should "
            "not be left indefinitely."
        )
    elif severity == "low":
        action = (
            "Include this in the backlog for future hardening efforts. "
            "While not urgent, addressing it improves the overall security "
            "posture over time."
        )
    else:
        action = (
            "Review this finding for informational purposes. No immediate "
            "action is required, but consider it during future security "
            "architecture reviews."
        )

    explanation = (
        f"[AI Suggestion - Proposed Explanation]\n\n"
        f"What this means: The finding '{title}' indicates "
        f"{description if description else 'a security concern'} "
        f"at severity level {severity.upper()}.\n\n"
        f"In simple terms: {analogy}\n\n"
        f"Potential impact: {impact}\n\n"
        f"Recommended action: {action}\n\n"
        f"[This explanation is based on the finding evidence: "
        f"'{finding_evidence[:200]}{'...' if len(str(finding_evidence)) > 200 else ''}'.]"
    )

    return {
        "explanation": explanation,
        "severity": severity,
        "analogy": analogy,
        "potential_impact": impact,
        "recommended_action": action,
        "evidence_reference": finding_evidence,
        "ai_label": "AI Suggestion - Proposed",
    }


# =========================================================================== #
# Tool 1: triage_findings
# =========================================================================== #

@server.tool(
    name="triage_findings",
    description=(
        "AI-powered triage of security findings. Takes a list of findings and "
        "returns them prioritized with rationale, recommended actions, and "
        "effort estimates. Also categorizes findings into immediate_action, "
        "short_term, long_term, and accepted_risk buckets. All suggestions "
        "are propose-only and evidence-grounded. No external LLM required."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": (
                        "Finding dict with: title, description, severity "
                        "(critical/high/medium/low/info), category (vuln/"
                        "misconfig/exposure/info), source_check, "
                        "exploitability_score (0-10), asset_criticality "
                        "(critical/high/medium/low), exposure "
                        "(internet/dmz/internal)"
                    ),
                },
                "description": "List of security findings to triage",
            },
        },
        "required": ["findings"],
    },
)
async def triage_findings(findings: list[dict]) -> dict:
    """Triage and prioritize security findings."""
    try:
        logger.info("triage_findings called", finding_count=len(findings))

        prioritized = triage_engine.prioritize(findings)
        categorized = triage_engine.categorize(findings)

        return ToolResult(
            success=True,
            data={
                "prioritized_findings": prioritized,
                "categories": {
                    "immediate_action": categorized["immediate_action"],
                    "short_term": categorized["short_term"],
                    "long_term": categorized["long_term"],
                    "accepted_risk": categorized["accepted_risk"],
                },
                "summary": categorized["summary"],
                "ai_label": "AI Suggestion - Proposed triage",
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "ai_copilot_triage",
                "target": f"{len(findings)}_findings",
                "content": json.dumps(
                    {
                        "finding_count": len(findings),
                        "summary": categorized["summary"],
                    },
                    indent=2,
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "finding_count": len(findings),
                "category_summary": categorized["summary"],
            },
        ).model_dump()
    except Exception as exc:
        logger.error("triage_findings failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# =========================================================================== #
# Tool 2: suggest_remediation
# =========================================================================== #

@server.tool(
    name="suggest_remediation",
    description=(
        "AI-powered remediation suggestion for a single security finding. "
        "Returns a detailed remediation plan with ordered steps, difficulty "
        "rating, references, verification steps, and alternative mitigations. "
        "Uses a comprehensive knowledge base of 18+ remediation patterns. "
        "All suggestions are propose-only and evidence-grounded."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "finding": {
                "type": "object",
                "description": (
                    "Finding dict with: title, description, severity, "
                    "category, source_check, remediation (if any)"
                ),
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "source_check": {"type": "string"},
                    "remediation": {"type": "string"},
                },
            },
            "asset": {
                "type": "object",
                "description": "Optional asset context (ip_address, hostname, os_guess, services)",
                "properties": {
                    "ip_address": {"type": "string"},
                    "hostname": {"type": "string"},
                    "os_guess": {"type": "string"},
                    "services": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "required": ["finding"],
    },
)
async def suggest_remediation(finding: dict, asset: dict | None = None) -> dict:
    """Suggest remediation for a finding."""
    try:
        logger.info(
            "suggest_remediation called",
            finding_title=finding.get("title", "unknown"),
        )

        result = remediation_advisor.suggest(finding, asset)

        return ToolResult(
            success=True,
            data=result,
            artifacts=[{
                "type": "raw_output",
                "tool": "ai_copilot_remediation",
                "target": finding.get("title", "unknown"),
                "content": json.dumps(result, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "finding_title": finding.get("title"),
                "difficulty": result.get("difficulty"),
                "step_count": len(result.get("steps", [])),
                "match_confidence": result.get("evidence", {}).get("match_confidence"),
            },
        ).model_dump()
    except Exception as exc:
        logger.error("suggest_remediation failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# =========================================================================== #
# Tool 3: suggest_mitre_mappings
# =========================================================================== #

@server.tool(
    name="suggest_mitre_mappings",
    description=(
        "Suggest MITRE ATT&CK technique mappings for a security finding. "
        "Uses keyword matching against a knowledge base of 20+ technique "
        "patterns. Returns technique IDs, names, tactics, confidence levels, "
        "and rationale. All suggestions are propose-only and evidence-grounded."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "finding": {
                "type": "object",
                "description": (
                    "Finding dict with: title, description, severity, "
                    "category, source_check"
                ),
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "source_check": {"type": "string"},
                },
            },
        },
        "required": ["finding"],
    },
)
async def suggest_mitre_mappings(finding: dict) -> dict:
    """Suggest MITRE ATT&CK mappings for a finding."""
    try:
        logger.info(
            "suggest_mitre_mappings called",
            finding_title=finding.get("title", "unknown"),
        )

        suggestions = _suggest_mitre(finding)

        return ToolResult(
            success=True,
            data={
                "suggestions": suggestions,
                "finding_title": finding.get("title", ""),
                "suggestion_count": len(suggestions),
                "ai_label": "AI Suggestion - Proposed MITRE mappings",
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "ai_copilot_mitre",
                "target": finding.get("title", "unknown"),
                "content": json.dumps(suggestions, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "finding_title": finding.get("title"),
                "suggestion_count": len(suggestions),
                "techniques": [s["technique_id"] for s in suggestions],
            },
        ).model_dump()
    except Exception as exc:
        logger.error("suggest_mitre_mappings failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# =========================================================================== #
# Tool 4: generate_narrative
# =========================================================================== #

@server.tool(
    name="generate_narrative",
    description=(
        "Generate an executive summary narrative from report data. Produces "
        "a multi-paragraph narrative covering executive summary, key findings, "
        "risk posture, and recommendations. Pure rule-based generation with "
        "no external LLM. All content is evidence-grounded and labeled as "
        "AI-generated."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "report_data": {
                "type": "object",
                "description": (
                    "Report data dict with: total_findings, critical_count, "
                    "high_count, medium_count, low_count, info_count, "
                    "total_assets, affected_assets, scan_date, scan_scope, "
                    "top_findings (list of {title, severity}), risk_level, "
                    "previous_risk_level, recommendations (list of strings)"
                ),
                "properties": {
                    "total_findings": {"type": "integer"},
                    "critical_count": {"type": "integer"},
                    "high_count": {"type": "integer"},
                    "medium_count": {"type": "integer"},
                    "low_count": {"type": "integer"},
                    "info_count": {"type": "integer"},
                    "total_assets": {"type": "integer"},
                    "affected_assets": {"type": "integer"},
                    "scan_date": {"type": "string"},
                    "scan_scope": {"type": "string"},
                    "top_findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {"type": "string"},
                            },
                        },
                    },
                    "risk_level": {"type": "string"},
                    "previous_risk_level": {"type": "string"},
                    "recommendations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "required": ["report_data"],
    },
)
async def generate_narrative(report_data: dict) -> dict:
    """Generate an executive summary narrative."""
    try:
        logger.info(
            "generate_narrative called",
            total_findings=report_data.get("total_findings", 0),
        )

        narrative = prompt_templates.generate_narrative(report_data)

        return ToolResult(
            success=True,
            data={
                "narrative": narrative,
                "ai_label": "AI Suggestion - Proposed narrative",
                "generation_method": "rule-based (no external LLM)",
            },
            artifacts=[{
                "type": "raw_output",
                "tool": "ai_copilot_narrative",
                "target": report_data.get("scan_scope", "report"),
                "content": narrative,
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "total_findings": report_data.get("total_findings"),
                "risk_level": report_data.get("risk_level"),
                "generation_method": "rule-based",
            },
        ).model_dump()
    except Exception as exc:
        logger.error("generate_narrative failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


# =========================================================================== #
# Tool 5: explain_risk
# =========================================================================== #

@server.tool(
    name="explain_risk",
    description=(
        "Explain a risk item in plain, non-technical language suitable for "
        "stakeholders and executives. Provides an analogy, potential impact, "
        "and recommended action. All explanations are evidence-grounded and "
        "labeled as AI Suggestions."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "risk_item": {
                "type": "object",
                "description": (
                    "Risk item dict with: title, description, severity "
                    "(critical/high/medium/low/info), risk_level, evidence"
                ),
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "risk_level": {"type": "string"},
                    "evidence": {"type": "string"},
                },
            },
        },
        "required": ["risk_item"],
    },
)
async def explain_risk(risk_item: dict) -> dict:
    """Explain a risk item in plain language."""
    try:
        logger.info(
            "explain_risk called",
            risk_title=risk_item.get("title", "unknown"),
        )

        explanation = _explain_risk_item(risk_item)

        return ToolResult(
            success=True,
            data=explanation,
            artifacts=[{
                "type": "raw_output",
                "tool": "ai_copilot_explain",
                "target": risk_item.get("title", "unknown"),
                "content": explanation["explanation"],
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "risk_title": risk_item.get("title"),
                "severity": explanation["severity"],
            },
        ).model_dump()
    except Exception as exc:
        logger.error("explain_risk failed", error=str(exc))
        return ToolResult(
            success=False,
            error=str(exc),
        ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
