"""HTML report generator for risk assessment data.

Generates complete, self-contained HTML documents with inline CSS styling.
No external dependencies (no Jinja2, no external CSS/JS).
"""

import html
from datetime import datetime

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Severity colour palette
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_BG_COLORS = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#eff6ff",
    "info": "#f9fafb",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _esc(value) -> str:
    """Safely HTML-escape any value, converting to string first."""
    if value is None:
        return ""
    return html.escape(str(value))


def _severity_badge(severity: str) -> str:
    sev = severity.lower() if severity else "info"
    color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:9999px;'
        f"font-size:0.75rem;font-weight:600;color:#fff;background:{color};\">"
        f"{_esc(sev.upper())}</span>"
    )


def _risk_badge(level: str) -> str:
    lvl = level.lower() if level else "low"
    color = SEVERITY_COLORS.get(lvl, SEVERITY_COLORS["info"])
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:9999px;'
        f"font-size:0.75rem;font-weight:600;color:#fff;background:{color};\">"
        f"{_esc(lvl.upper())}</span>"
    )


# ---------------------------------------------------------------------------
# CSS stylesheet (inline in <style>)
# ---------------------------------------------------------------------------
_CSS = """\
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b; background: #f8fafc; line-height: 1.6; padding: 0; margin: 0;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px 32px 48px; }
header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: #fff; padding: 40px 32px 32px;
}
header h1 { font-size: 1.75rem; font-weight: 700; margin-bottom: 4px; }
header p { opacity: 0.8; font-size: 0.95rem; }
h2 {
    font-size: 1.25rem; font-weight: 700; margin: 32px 0 16px;
    padding-bottom: 8px; border-bottom: 2px solid #e2e8f0;
}
.card {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
    padding: 20px 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.metrics { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; }
.metric-box {
    flex: 1 1 140px; background: #fff; border: 1px solid #e2e8f0;
    border-radius: 8px; padding: 16px 20px; text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.metric-box .value { font-size: 2rem; font-weight: 700; }
.metric-box .label { font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th {
    text-align: left; padding: 10px 12px; background: #f1f5f9;
    font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0;
}
td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
tr:hover td { background: #f8fafc; }
.finding-group { margin-bottom: 24px; }
.finding-group h3 { font-size: 1rem; font-weight: 600; margin-bottom: 8px; }
.evidence { background: #f1f5f9; border-radius: 4px; padding: 8px 12px; font-size: 0.8rem; font-family: monospace; white-space: pre-wrap; word-break: break-all; margin-top: 6px; color: #334155; }
.footer { text-align: center; color: #94a3b8; font-size: 0.75rem; margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
@media (max-width: 768px) {
    .container { padding: 16px; }
    header { padding: 24px 16px; }
    .metrics { flex-direction: column; }
    table { font-size: 0.8rem; }
    th, td { padding: 6px 8px; }
}
"""


class HTMLReportGenerator:
    """Generates a self-contained HTML report from risk assessment run data."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, data: dict) -> str:
        """Generate a complete standalone HTML report.

        Parameters
        ----------
        data : dict
            Expected keys (all optional, degrade gracefully):
            - assets: list[dict]
            - findings: list[dict]
            - risks: list[dict]
            - mitre_mappings: list[dict]
            - metadata: dict  (run_id, timestamp, scope, ...)
        """
        logger.info("Generating HTML report", keys=list(data.keys()))

        assets = data.get("assets", [])
        findings = data.get("findings", [])
        risks = data.get("risks", [])
        mitre_mappings = data.get("mitre_mappings", [])
        metadata = data.get("metadata", {})

        timestamp = metadata.get("timestamp", datetime.utcnow().isoformat())
        run_id = metadata.get("run_id", "N/A")
        scope = metadata.get("scope", "Full assessment")

        sections = [
            self._section_executive_summary(assets, findings, risks, metadata),
            self._section_asset_inventory(assets),
            self._section_findings(findings),
            self._section_risk_register(risks),
            self._section_mitre(mitre_mappings),
            self._section_audit_trail(metadata),
        ]

        body = "\n".join(sections)

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Risk Assessment Report &mdash; {_esc(run_id)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>Risk Assessment Report</h1>
  <p>Run ID: {_esc(run_id)} &middot; Generated: {_esc(timestamp)} &middot; Scope: {_esc(scope)}</p>
</header>
<div class="container">
{body}
<div class="footer">
    Generated by Risk-App Reporting Engine &middot; {_esc(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))}
</div>
</div>
</body>
</html>"""

        logger.info(
            "HTML report generated",
            length=len(report),
            assets=len(assets),
            findings=len(findings),
            risks=len(risks),
        )
        return report

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _section_executive_summary(
        self, assets: list, findings: list, risks: list, metadata: dict
    ) -> str:
        total_assets = len(assets)
        total_findings = len(findings)
        total_risks = len(risks)

        # Count by severity
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Count by risk level
        risk_counts: dict[str, int] = {}
        for r in risks:
            lvl = (r.get("risk_level") or "low").lower()
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

        critical_findings = sev_counts.get("critical", 0)
        high_findings = sev_counts.get("high", 0)
        critical_risks = risk_counts.get("critical", 0)
        high_risks = risk_counts.get("high", 0)

        overall_color = SEVERITY_COLORS["info"]
        overall_label = "LOW"
        if critical_risks > 0 or critical_findings > 0:
            overall_color = SEVERITY_COLORS["critical"]
            overall_label = "CRITICAL"
        elif high_risks > 0 or high_findings > 0:
            overall_color = SEVERITY_COLORS["high"]
            overall_label = "HIGH"
        elif risk_counts.get("medium", 0) > 0 or sev_counts.get("medium", 0) > 0:
            overall_color = SEVERITY_COLORS["medium"]
            overall_label = "MEDIUM"
        elif total_findings > 0 or total_risks > 0:
            overall_color = SEVERITY_COLORS["low"]
            overall_label = "LOW"

        # Severity breakdown pills for findings
        sev_pills = ""
        for sev in SEVERITY_ORDER:
            count = sev_counts.get(sev, 0)
            if count > 0:
                sev_pills += f" {_severity_badge(sev)} &times; {count} &nbsp;"

        # Risk level breakdown pills
        risk_pills = ""
        for lvl in SEVERITY_ORDER:
            count = risk_counts.get(lvl, 0)
            if count > 0:
                risk_pills += f" {_risk_badge(lvl)} &times; {count} &nbsp;"

        return f"""
<h2>Executive Summary</h2>
<div class="metrics">
  <div class="metric-box">
    <div class="value" style="color:{overall_color};">{_esc(overall_label)}</div>
    <div class="label">Overall Risk</div>
  </div>
  <div class="metric-box">
    <div class="value">{total_assets}</div>
    <div class="label">Assets Assessed</div>
  </div>
  <div class="metric-box">
    <div class="value">{total_findings}</div>
    <div class="label">Findings</div>
  </div>
  <div class="metric-box">
    <div class="value" style="color:{SEVERITY_COLORS['critical']};">{critical_findings + critical_risks}</div>
    <div class="label">Critical Items</div>
  </div>
  <div class="metric-box">
    <div class="value" style="color:{SEVERITY_COLORS['high']};">{high_findings + high_risks}</div>
    <div class="label">High Items</div>
  </div>
</div>
<div class="card">
  <p><strong>Findings by severity:</strong> {sev_pills if sev_pills else "None"}</p>
  <p style="margin-top:8px;"><strong>Risk items by level:</strong> {risk_pills if risk_pills else "None"}</p>
</div>
"""

    def _section_asset_inventory(self, assets: list) -> str:
        if not assets:
            return '<h2>Asset Inventory</h2><div class="card"><p>No assets recorded.</p></div>'

        rows = ""
        for a in assets:
            rows += (
                f"<tr>"
                f"<td>{_esc(a.get('ip_address', 'N/A'))}</td>"
                f"<td>{_esc(a.get('hostname', ''))}</td>"
                f"<td>{_esc(a.get('asset_type', ''))}</td>"
                f"<td>{_esc(a.get('zone', ''))}</td>"
                f"<td>{_esc(a.get('criticality', ''))}</td>"
                f"<td>{_esc(a.get('os_guess', ''))}</td>"
                f"<td>{_esc(', '.join(str(p) for p in a.get('open_ports', [])))}</td>"
                f"</tr>\n"
            )

        return f"""
<h2>Asset Inventory</h2>
<div class="card" style="overflow-x:auto;">
<table>
<thead>
<tr><th>IP Address</th><th>Hostname</th><th>Type</th><th>Zone</th><th>Criticality</th><th>OS</th><th>Open Ports</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
"""

    def _section_findings(self, findings: list) -> str:
        if not findings:
            return '<h2>Findings</h2><div class="card"><p>No findings recorded.</p></div>'

        # Group by severity
        grouped: dict[str, list] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            grouped.setdefault(sev, []).append(f)

        html_parts = ['<h2>Findings</h2>']

        for sev in SEVERITY_ORDER:
            group = grouped.get(sev, [])
            if not group:
                continue

            bg = SEVERITY_BG_COLORS.get(sev, SEVERITY_BG_COLORS["info"])
            color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])

            html_parts.append(
                f'<div class="finding-group">'
                f'<h3>{_severity_badge(sev)} {_esc(sev.upper())} ({len(group)})</h3>'
            )

            for f in group:
                evidence_block = ""
                evidence = f.get("evidence", "")
                if evidence:
                    evidence_block = f'<div class="evidence">{_esc(evidence)}</div>'

                remediation_block = ""
                remediation = f.get("remediation")
                if remediation:
                    remediation_block = (
                        f'<p style="margin-top:6px;"><strong>Remediation:</strong> '
                        f"{_esc(remediation)}</p>"
                    )

                cve_block = ""
                cve_ids = f.get("cve_ids", [])
                if cve_ids:
                    cve_block = (
                        f'<p style="margin-top:4px;"><strong>CVEs:</strong> '
                        f"{_esc(', '.join(cve_ids))}</p>"
                    )

                html_parts.append(
                    f'<div class="card" style="border-left:4px solid {color};background:{bg};">'
                    f'<p><strong>{_esc(f.get("title", "Untitled"))}</strong>'
                    f' <span style="color:#64748b;font-size:0.8rem;">({_esc(f.get("source_tool", ""))} / {_esc(f.get("source_check", ""))})</span></p>'
                    f'<p style="margin-top:4px;color:#475569;">{_esc(f.get("description", ""))}</p>'
                    f"{cve_block}"
                    f"{remediation_block}"
                    f"{evidence_block}"
                    f"</div>"
                )

            html_parts.append("</div>")

        return "\n".join(html_parts)

    def _section_risk_register(self, risks: list) -> str:
        if not risks:
            return '<h2>Risk Register</h2><div class="card"><p>No risk items recorded.</p></div>'

        rows = ""
        # Sort: critical first
        order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_risks = sorted(
            risks, key=lambda r: order_map.get((r.get("risk_level") or "low").lower(), 99)
        )

        for r in sorted_risks:
            rows += (
                f"<tr>"
                f"<td>{_esc(r.get('asset_ip', r.get('asset', {}).get('ip_address', 'N/A')))}</td>"
                f"<td>{_esc(r.get('scenario', r.get('title', '')))}</td>"
                f"<td>{_risk_badge(r.get('risk_level', 'low'))}</td>"
                f"<td>{_esc(r.get('likelihood', ''))}</td>"
                f"<td>{_esc(r.get('impact', ''))}</td>"
                f"<td>{_esc(r.get('recommended_treatment', r.get('treatment', '')))}</td>"
                f"</tr>\n"
            )

        return f"""
<h2>Risk Register</h2>
<div class="card" style="overflow-x:auto;">
<table>
<thead>
<tr><th>Asset</th><th>Scenario</th><th>Risk Level</th><th>Likelihood</th><th>Impact</th><th>Treatment</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
"""

    def _section_mitre(self, mitre_mappings: list) -> str:
        if not mitre_mappings:
            return '<h2>MITRE ATT&amp;CK Coverage</h2><div class="card"><p>No MITRE ATT&amp;CK mappings recorded.</p></div>'

        rows = ""
        for m in mitre_mappings:
            technique_id = m.get("technique_id", "")
            technique_name = m.get("technique_name", m.get("name", ""))
            tactics = m.get("tactics", [])
            if isinstance(tactics, list):
                tactics_str = ", ".join(str(t) for t in tactics)
            else:
                tactics_str = str(tactics)

            confidence = m.get("confidence", "")
            finding_title = m.get("finding_title", m.get("source", ""))

            rows += (
                f"<tr>"
                f"<td><strong>{_esc(technique_id)}</strong></td>"
                f"<td>{_esc(technique_name)}</td>"
                f"<td>{_esc(tactics_str)}</td>"
                f"<td>{_esc(confidence)}</td>"
                f"<td>{_esc(finding_title)}</td>"
                f"</tr>\n"
            )

        return f"""
<h2>MITRE ATT&amp;CK Coverage</h2>
<div class="card" style="overflow-x:auto;">
<table>
<thead>
<tr><th>Technique ID</th><th>Technique Name</th><th>Tactics</th><th>Confidence</th><th>Source Finding</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
"""

    def _section_audit_trail(self, metadata: dict) -> str:
        if not metadata:
            return '<h2>Audit Trail</h2><div class="card"><p>No audit metadata available.</p></div>'

        audit_items = ""

        standard_keys = [
            ("run_id", "Run ID"),
            ("timestamp", "Timestamp"),
            ("scope", "Scope"),
            ("scanner_version", "Scanner Version"),
            ("initiated_by", "Initiated By"),
            ("duration_seconds", "Duration (s)"),
            ("target_network", "Target Network"),
            ("policy", "Policy"),
        ]

        rendered_keys = set()
        for key, label in standard_keys:
            val = metadata.get(key)
            if val is not None:
                audit_items += f"<tr><td><strong>{_esc(label)}</strong></td><td>{_esc(val)}</td></tr>\n"
                rendered_keys.add(key)

        # Render any remaining keys
        for key, val in metadata.items():
            if key not in rendered_keys:
                audit_items += f"<tr><td><strong>{_esc(key)}</strong></td><td>{_esc(val)}</td></tr>\n"

        return f"""
<h2>Audit Trail</h2>
<div class="card">
<table>
<tbody>
{audit_items}
</tbody>
</table>
</div>
"""
