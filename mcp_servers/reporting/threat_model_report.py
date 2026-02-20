"""Threat Modeling HTML report generator.

Generates a self-contained HTML document with inline CSS for threat modeling results.
Pattern follows html_report.py — no external dependencies.
"""

import html
from datetime import datetime

import structlog

logger = structlog.get_logger()

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fffbeb",
    "low": "#eff6ff",
    "info": "#f9fafb",
}

STRIDE_LABELS = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information Disclosure",
    "denial_of_service": "Denial of Service",
    "elevation_of_privilege": "Elevation of Privilege",
}

C4_LABELS = {
    "system_context": "System Context (L1)",
    "container": "Container / Zone (L2)",
    "component": "Component / Asset (L3)",
}


def _esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _badge(text: str, color: str, bg: str) -> str:
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:9999px;'
        f'font-size:0.75rem;font-weight:600;color:#fff;background:{color};">'
        f'{_esc(text)}</span>'
    )


def _confidence_bar(confidence: float) -> str:
    pct = int(confidence * 100)
    color = "#dc2626" if pct >= 70 else "#d97706" if pct >= 40 else "#2563eb"
    return (
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="flex:1;background:#e5e7eb;border-radius:9999px;height:6px;">'
        f'<div style="width:{pct}%;background:{color};border-radius:9999px;height:6px;"></div>'
        f'</div>'
        f'<span style="font-size:0.75rem;font-weight:600;color:{color};">{pct}%</span>'
        f'</div>'
    )


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
    padding: 20px; margin-bottom: 16px;
}
.stats-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 24px;
}
.stat-card {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
    padding: 16px; text-align: center;
}
.stat-value { font-size: 2rem; font-weight: 700; }
.stat-label { font-size: 0.8rem; color: #64748b; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th { text-align: left; padding: 10px 12px; background: #f1f5f9; border-bottom: 2px solid #e2e8f0; font-weight: 600; }
td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; }
tr:hover td { background: #f8fafc; }
.footer { text-align: center; padding: 24px; color: #94a3b8; font-size: 0.75rem; }
"""


class ThreatModelingReportGenerator:
    """Generate a self-contained HTML threat modeling report."""

    @staticmethod
    def generate(data: dict) -> str:
        """Generate HTML report from threat modeling results.

        Args:
            data: Dict with keys: summary, threats_by_c4, threats_by_stride,
                  assets_analyzed, risk_treatments (optional)
        """
        summary = data.get("summary", {})
        threats_by_c4 = data.get("threats_by_c4", {})
        threats_by_stride = data.get("threats_by_stride", {})
        assets = data.get("assets_analyzed", [])
        risk_treatments = data.get("risk_treatments", [])
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        parts = [
            f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>",
            f"<title>Threat Modeling Report — {generated_at}</title>",
            f"<style>{_CSS}</style></head><body>",
            # Header
            f"<header><h1>Threat Modeling Report</h1>",
            f"<p>Generated {generated_at}</p></header>",
            f"<div class='container'>",
        ]

        # Executive Summary
        total = summary.get("threats_created", 0)
        by_c4 = summary.get("by_c4_level", {})
        by_stride = summary.get("by_stride", {})
        total_assets = summary.get("total_assets", 0)

        parts.append("<h2>Executive Summary</h2>")
        parts.append("<div class='stats-grid'>")
        parts.append(f"<div class='stat-card'><div class='stat-value'>{total}</div><div class='stat-label'>Total Threats</div></div>")
        parts.append(f"<div class='stat-card'><div class='stat-value'>{total_assets}</div><div class='stat-label'>Assets Analyzed</div></div>")
        parts.append(f"<div class='stat-card'><div class='stat-value'>{by_c4.get('system_context', 0)}</div><div class='stat-label'>System Context (L1)</div></div>")
        parts.append(f"<div class='stat-card'><div class='stat-value'>{by_c4.get('container', 0)}</div><div class='stat-label'>Container (L2)</div></div>")
        parts.append(f"<div class='stat-card'><div class='stat-value'>{by_c4.get('component', 0)}</div><div class='stat-label'>Component (L3)</div></div>")
        stride_total = sum(by_stride.values()) if by_stride else 0
        top_stride = max(by_stride.items(), key=lambda x: x[1])[0] if by_stride else "N/A"
        parts.append(f"<div class='stat-card'><div class='stat-value'>{STRIDE_LABELS.get(top_stride, top_stride)}</div><div class='stat-label'>Top STRIDE Category</div></div>")
        parts.append("</div>")

        # Assets Analyzed
        if assets:
            parts.append("<h2>Assets Analyzed</h2>")
            parts.append("<table><thead><tr><th>IP Address</th><th>Hostname</th><th>Type</th><th>Zone</th><th>Criticality</th></tr></thead><tbody>")
            for a in assets:
                crit = a.get("criticality", "medium")
                color = SEVERITY_COLORS.get(crit, SEVERITY_COLORS["info"])
                parts.append(
                    f"<tr><td style='font-family:monospace;'>{_esc(a.get('ip_address', ''))}</td>"
                    f"<td>{_esc(a.get('hostname', '-'))}</td>"
                    f"<td>{_esc(a.get('asset_type', '-'))}</td>"
                    f"<td>{_esc(a.get('zone', '-'))}</td>"
                    f"<td>{_badge(crit.upper(), color, '')}</td></tr>"
                )
            parts.append("</tbody></table>")

        # Threats by C4 Level
        for c4_level in ["system_context", "container", "component"]:
            threats = threats_by_c4.get(c4_level, [])
            if not threats:
                continue
            label = C4_LABELS.get(c4_level, c4_level)
            parts.append(f"<h2>Threats — {_esc(label)} ({len(threats)})</h2>")
            parts.append("<table><thead><tr><th>Threat</th><th>STRIDE</th><th>Zone</th><th>Confidence</th></tr></thead><tbody>")
            for t in threats:
                stride_type = t.get("threat_type", "unknown")
                stride_label = STRIDE_LABELS.get(stride_type, stride_type)
                conf = t.get("confidence", 0)
                parts.append(
                    f"<tr><td><strong>{_esc(t.get('title', ''))}</strong>"
                    f"<br><span style='font-size:0.8rem;color:#64748b;'>{_esc(t.get('description', '')[:150])}</span></td>"
                    f"<td>{_esc(stride_label)}</td>"
                    f"<td>{_esc(t.get('zone', '-'))}</td>"
                    f"<td style='min-width:120px;'>{_confidence_bar(conf)}</td></tr>"
                )
            parts.append("</tbody></table>")

        # STRIDE Analysis
        if by_stride:
            parts.append("<h2>STRIDE Analysis</h2>")
            parts.append("<div class='card'>")
            max_count = max(by_stride.values()) if by_stride else 1
            for stride_key in ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"]:
                count = by_stride.get(stride_key, 0)
                pct = int((count / max_count) * 100) if max_count > 0 else 0
                label = STRIDE_LABELS.get(stride_key, stride_key)
                parts.append(
                    f"<div style='display:flex;align-items:center;gap:12px;margin-bottom:8px;'>"
                    f"<span style='width:160px;font-size:0.85rem;font-weight:500;'>{_esc(label)}</span>"
                    f"<div style='flex:1;background:#e5e7eb;border-radius:9999px;height:8px;'>"
                    f"<div style='width:{pct}%;background:#6366f1;border-radius:9999px;height:8px;'></div></div>"
                    f"<span style='width:40px;text-align:right;font-weight:600;'>{count}</span></div>"
                )
            parts.append("</div>")

        # Risk Treatments
        if risk_treatments:
            parts.append("<h2>Risk Treatment Recommendations</h2>")
            parts.append("<table><thead><tr><th>Risk Scenario</th><th>Level</th><th>Treatment</th><th>Rationale</th></tr></thead><tbody>")
            for r in risk_treatments:
                level = r.get("risk_level", "medium")
                color = SEVERITY_COLORS.get(level, SEVERITY_COLORS["info"])
                parts.append(
                    f"<tr><td>{_esc(r.get('scenario', ''))}</td>"
                    f"<td>{_badge(level.upper(), color, '')}</td>"
                    f"<td>{_esc(r.get('treatment', '-'))}</td>"
                    f"<td>{_esc(r.get('rationale', ''))}</td></tr>"
                )
            parts.append("</tbody></table>")

        # Risk Summary
        parts.append("<h2>Risk Summary</h2>")
        parts.append("<div class='card'>")
        parts.append(f"<p><strong>Total threats identified:</strong> {total}</p>")
        parts.append(f"<p><strong>Assets analyzed:</strong> {total_assets}</p>")
        parts.append(f"<p><strong>C4 Levels covered:</strong> System Context, Container, Component</p>")
        if by_stride:
            top_3 = sorted(by_stride.items(), key=lambda x: x[1], reverse=True)[:3]
            top_str = ", ".join(f"{STRIDE_LABELS.get(k, k)} ({v})" for k, v in top_3)
            parts.append(f"<p><strong>Top threat categories:</strong> {_esc(top_str)}</p>")
        parts.append("</div>")

        # Footer
        parts.append("</div>")
        parts.append(f"<div class='footer'>Generated by Risk Platform — Threat Modeling Module — {generated_at}</div>")
        parts.append("</body></html>")

        return "\n".join(parts)
