"""PDF report generator for risk assessment data.

Uses reportlab (pure Python, no system dependencies) to generate proper PDF
documents from risk assessment data.
"""

import base64
import io
import os
from datetime import datetime

import structlog

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)

logger = structlog.get_logger()

# Severity color mapping for reportlab
SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#d97706"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#6b7280"),
}

SEVERITY_BG = {
    "critical": colors.HexColor("#fef2f2"),
    "high": colors.HexColor("#fff7ed"),
    "medium": colors.HexColor("#fffbeb"),
    "low": colors.HexColor("#eff6ff"),
    "info": colors.HexColor("#f9fafb"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _get_styles():
    """Build custom paragraph styles."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=24, spaceAfter=6, textColor=colors.HexColor("#1e293b"),
    ))
    styles.add(ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"],
        fontSize=12, textColor=colors.HexColor("#64748b"), spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"],
        fontSize=16, spaceBefore=16, spaceAfter=8,
        textColor=colors.HexColor("#1e293b"),
    ))
    styles.add(ParagraphStyle(
        "SubHeading", parent=styles["Heading3"],
        fontSize=12, spaceBefore=10, spaceAfter=6,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        "BodySmall", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#475569"),
    ))
    return styles


class PDFReportGenerator:
    """Generates PDF reports from risk assessment data using reportlab."""

    def __init__(self):
        from mcp_servers.reporting.html_report import HTMLReportGenerator
        self._html_generator = HTMLReportGenerator()

    def generate(self, data: dict, output_path: str) -> str:
        """Generate a PDF report and write to disk."""
        logger.info("Generating PDF report", output_path=output_path)
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        pdf_bytes = self._build_pdf(data)
        with open(output_path, "wb") as fh:
            fh.write(pdf_bytes)

        logger.info("PDF written successfully", path=output_path)
        return output_path

    def generate_from_html(self, html: str, output_path: str) -> str:
        """For backwards compatibility — generates PDF from data, ignoring HTML."""
        # We can't convert arbitrary HTML with reportlab, so generate from scratch
        # This is only called as fallback; the main path uses generate() directly
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        # Write a minimal PDF with the HTML as text content
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = _get_styles()
        story = [Paragraph("Risk Assessment Report", styles["ReportTitle"])]
        story.append(Paragraph("Generated from HTML content", styles["ReportSubtitle"]))
        doc.build(story)
        pdf_bytes = buf.getvalue()
        with open(output_path, "wb") as fh:
            fh.write(pdf_bytes)
        return output_path

    def generate_base64(self, data: dict) -> tuple[str, str]:
        """Generate a PDF and return as base64-encoded string.

        Returns (base64_content, "pdf").
        """
        try:
            pdf_bytes = self._build_pdf(data)
            return base64.b64encode(pdf_bytes).decode("ascii"), "pdf"
        except Exception as e:
            logger.error("PDF generation failed", error=str(e))
            raise

    def _build_pdf(self, data: dict) -> bytes:
        """Build a complete PDF report and return as bytes."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=20 * mm, bottomMargin=20 * mm,
        )
        styles = _get_styles()
        story: list = []

        # --- Title Page ---
        story.append(Spacer(1, 60))
        story.append(Paragraph("Risk Assessment Report", styles["ReportTitle"]))

        run_id = data.get("run_id", "")
        generated = data.get("generated_at") or datetime.utcnow().isoformat()
        story.append(Paragraph(
            f"Generated: {generated[:19].replace('T', ' ')}"
            + (f" &nbsp;|&nbsp; Run: {run_id[:8]}" if run_id else ""),
            styles["ReportSubtitle"],
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 20))

        # --- Executive Summary ---
        summary = data.get("summary", {})
        if summary:
            story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
            summary_items = [
                ("Total Assets", summary.get("total_assets", 0)),
                ("Total Findings", summary.get("total_findings", 0)),
                ("Total Threats", summary.get("total_threats", 0)),
                ("Total Risks", summary.get("total_risks", 0)),
            ]
            summary_data = [["Metric", "Value"]]
            for label, val in summary_items:
                summary_data.append([label, str(val)])

            t = Table(summary_data, colWidths=[3 * inch, 2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ]))
            story.append(t)
            story.append(Spacer(1, 16))

        # --- Risk Distribution ---
        risk_dist = data.get("risk_distribution") or summary.get("risk_distribution", {})
        if risk_dist:
            story.append(Paragraph("Risk Distribution", styles["SubHeading"]))
            risk_data = [["Level", "Count"]]
            for level in ["critical", "high", "medium", "low"]:
                count = risk_dist.get(level, 0)
                if count or True:  # always show all levels
                    risk_data.append([level.upper(), str(count)])

            t = Table(risk_data, colWidths=[2 * inch, 1.5 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ]))
            # Color-code rows
            for i, level in enumerate(["critical", "high", "medium", "low"], 1):
                if i < len(risk_data):
                    bg = SEVERITY_BG.get(level, colors.white)
                    t.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), bg)]))
            story.append(t)
            story.append(Spacer(1, 16))

        # --- Findings Table ---
        findings = data.get("findings", [])
        if findings:
            story.append(Paragraph(f"Findings ({len(findings)})", styles["SectionHeading"]))

            # Group by severity
            for sev in SEVERITY_ORDER:
                sev_findings = [f for f in findings if (f.get("severity") or "info").lower() == sev]
                if not sev_findings:
                    continue

                story.append(Paragraph(f"{sev.upper()} ({len(sev_findings)})", styles["SubHeading"]))

                table_data = [["Title", "Category", "Asset", "Status"]]
                for f in sev_findings[:30]:  # Limit per severity to avoid huge PDFs
                    asset_info = ""
                    if f.get("asset"):
                        a = f["asset"]
                        asset_info = a.get("ip_address", "")
                        if a.get("hostname"):
                            asset_info += f" ({a['hostname']})"
                    elif f.get("asset_ip"):
                        asset_info = f["asset_ip"]

                    table_data.append([
                        str(f.get("title", ""))[:80],
                        str(f.get("category", "")),
                        asset_info,
                        str(f.get("status", "open")),
                    ])

                col_widths = [3.2 * inch, 1 * inch, 1.5 * inch, 0.8 * inch]
                t = Table(table_data, colWidths=col_widths, repeatRows=1)
                sev_color = SEVERITY_COLORS.get(sev, colors.gray)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))

        # --- Risks Table ---
        risks = data.get("risks", [])
        if risks:
            story.append(PageBreak())
            story.append(Paragraph(f"Risk Scenarios ({len(risks)})", styles["SectionHeading"]))

            table_data = [["Level", "Scenario", "Likelihood", "Impact", "Treatment", "Status"]]
            for r in risks[:50]:
                table_data.append([
                    str(r.get("risk_level", "")).upper(),
                    str(r.get("scenario", ""))[:100],
                    str(r.get("likelihood", "")),
                    str(r.get("impact", "")),
                    str(r.get("treatment") or "—"),
                    str(r.get("status", "")),
                ])

            col_widths = [0.7 * inch, 2.5 * inch, 0.8 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t)
            story.append(Spacer(1, 16))

        # --- Threats Table ---
        threats = data.get("threats", [])
        if threats:
            story.append(Paragraph(f"Threats ({len(threats)})", styles["SectionHeading"]))

            table_data = [["Type", "Title", "Zone", "Confidence", "Source"]]
            for t_data in threats[:50]:
                table_data.append([
                    str(t_data.get("threat_type", "")),
                    str(t_data.get("title", ""))[:80],
                    str(t_data.get("zone") or "—"),
                    f"{round((t_data.get('confidence') or 0) * 100)}%",
                    str(t_data.get("source", "")),
                ])

            col_widths = [1 * inch, 2.5 * inch, 0.7 * inch, 0.8 * inch, 0.7 * inch]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(t)
            story.append(Spacer(1, 16))

        # --- Recommendations ---
        recommendations = data.get("recommendations", [])
        if recommendations:
            story.append(Paragraph("Recommendations", styles["SectionHeading"]))
            for i, rec in enumerate(recommendations[:20], 1):
                if isinstance(rec, dict):
                    text = rec.get("text") or rec.get("recommendation", "")
                    priority = rec.get("priority", "")
                    story.append(Paragraph(
                        f"<b>{i}.</b> {text}" + (f" <i>[{priority}]</i>" if priority else ""),
                        styles["BodySmall"],
                    ))
                else:
                    story.append(Paragraph(f"<b>{i}.</b> {rec}", styles["BodySmall"]))
                story.append(Spacer(1, 4))

        # --- Footer ---
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1")))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Generated by Risk-App3.0 &nbsp;|&nbsp; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["BodySmall"],
        ))

        doc.build(story)
        return buf.getvalue()
