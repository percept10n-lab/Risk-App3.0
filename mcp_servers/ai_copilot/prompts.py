"""Prompt templates for AI Defense Copilot.

Contains prompt template strings for each AI capability (used if external LLM
integration is enabled) and a rule-based narrative generator that works
without any external model.
"""

import structlog

logger = structlog.get_logger()


class PromptTemplates:
    """Prompt templates and rule-based text generation for the AI Copilot."""

    # --------------------------------------------------------------------- #
    # Prompt templates (for optional external LLM integration)
    # --------------------------------------------------------------------- #

    TRIAGE_PROMPT = (
        "You are a senior security analyst performing triage on security findings.\n"
        "\n"
        "Findings to triage:\n"
        "{findings_json}\n"
        "\n"
        "For each finding, determine:\n"
        "1. Priority score (0-100) based on severity, exploitability, asset "
        "criticality, and exposure.\n"
        "2. A concise rationale for the assigned priority.\n"
        "3. A recommended first action.\n"
        "4. Estimated remediation effort (low/medium/high).\n"
        "\n"
        "Return the findings sorted by priority score descending. Every "
        "recommendation must reference specific evidence from the finding data. "
        "Label all outputs as 'AI Suggestion'."
    )

    REMEDIATION_PROMPT = (
        "You are a security remediation advisor.\n"
        "\n"
        "Finding:\n"
        "{finding_json}\n"
        "\n"
        "Asset context (if available):\n"
        "{asset_json}\n"
        "\n"
        "Provide a remediation plan with:\n"
        "1. One-line summary recommendation.\n"
        "2. Ordered remediation steps with specific commands or config changes.\n"
        "3. Difficulty rating (easy/moderate/hard).\n"
        "4. Reference links to official documentation.\n"
        "5. Verification steps to confirm the fix.\n"
        "6. Alternative mitigations if the primary fix is not feasible.\n"
        "\n"
        "All recommendations must be evidence-grounded and labeled as 'Proposed'."
    )

    NARRATIVE_PROMPT = (
        "You are writing an executive security summary for leadership.\n"
        "\n"
        "Report data:\n"
        "{report_json}\n"
        "\n"
        "Generate a four-paragraph narrative covering:\n"
        "1. Executive Summary - overall posture and assessment scope.\n"
        "2. Key Findings - the most important discoveries with evidence.\n"
        "3. Risk Posture - overall risk level and trending.\n"
        "4. Recommendations - prioritized actions for improvement.\n"
        "\n"
        "Write in clear, non-technical language suitable for C-level executives. "
        "Every statement must be supported by specific data from the report."
    )

    RISK_EXPLANATION_PROMPT = (
        "You are a security advisor explaining a risk item to a non-technical "
        "stakeholder.\n"
        "\n"
        "Risk item:\n"
        "{risk_json}\n"
        "\n"
        "Provide:\n"
        "1. A plain-language explanation of what this risk means.\n"
        "2. A real-world analogy to illustrate the risk.\n"
        "3. What could happen if this risk is not addressed (impact).\n"
        "4. What the organization should do about it.\n"
        "\n"
        "Avoid jargon. Ground every statement in the specific evidence provided. "
        "Label the output as 'AI Suggestion'."
    )

    MITRE_SUGGESTION_PROMPT = (
        "You are a threat intelligence analyst mapping security findings to "
        "the MITRE ATT&CK framework.\n"
        "\n"
        "Finding:\n"
        "{finding_json}\n"
        "\n"
        "Suggest the most relevant MITRE ATT&CK techniques with:\n"
        "1. Technique ID and name.\n"
        "2. Tactic (the ATT&CK column).\n"
        "3. Confidence level (high/medium/low) and why.\n"
        "4. How this finding relates to the technique.\n"
        "\n"
        "Only suggest techniques with clear evidence from the finding. "
        "Label all suggestions as 'Proposed'."
    )

    # --------------------------------------------------------------------- #
    # Rule-based narrative generator (no LLM required)
    # --------------------------------------------------------------------- #

    @staticmethod
    def generate_narrative(data: dict) -> str:
        """Generate an executive summary narrative using rule-based logic.

        Args:
            data: Report data dict, expected keys:
                - total_findings (int)
                - critical_count (int)
                - high_count (int)
                - medium_count (int)
                - low_count (int)
                - info_count (int)
                - total_assets (int)
                - affected_assets (int)
                - scan_date (str)
                - scan_scope (str)
                - top_findings (list[dict])  - each with title, severity
                - risk_level (str)  - overall risk posture
                - previous_risk_level (str | None) - for trending
                - recommendations (list[str]) - ordered recommendations

        Returns:
            Multi-paragraph executive narrative string.
        """
        logger.info("Generating rule-based narrative", data_keys=list(data.keys()))

        total_findings = data.get("total_findings", 0)
        critical = data.get("critical_count", 0)
        high = data.get("high_count", 0)
        medium = data.get("medium_count", 0)
        low = data.get("low_count", 0)
        info = data.get("info_count", 0)
        total_assets = data.get("total_assets", 0)
        affected_assets = data.get("affected_assets", 0)
        scan_date = data.get("scan_date", "unknown date")
        scan_scope = data.get("scan_scope", "the target environment")
        top_findings = data.get("top_findings", [])
        risk_level = data.get("risk_level", "medium")
        previous_risk_level = data.get("previous_risk_level")
        recommendations = data.get("recommendations", [])

        # ---- Executive Summary paragraph ----
        if critical > 0:
            urgency = (
                "requires immediate attention due to the presence of "
                f"critical-severity findings"
            )
        elif high > 0:
            urgency = (
                "warrants prompt action given the identification of "
                f"high-severity findings"
            )
        elif medium > 0:
            urgency = (
                "presents a moderate risk posture with several findings "
                "that should be addressed in the near term"
            )
        else:
            urgency = "reflects a generally healthy security posture with only minor observations"

        exec_summary = (
            f"[AI Suggestion - Proposed Narrative] A security assessment of "
            f"{scan_scope} was conducted on {scan_date}, covering "
            f"{total_assets} asset(s). The assessment identified "
            f"{total_findings} finding(s) across {affected_assets} affected "
            f"asset(s). The overall posture {urgency}."
        )

        # ---- Key Findings paragraph ----
        severity_breakdown_parts = []
        if critical > 0:
            severity_breakdown_parts.append(f"{critical} critical")
        if high > 0:
            severity_breakdown_parts.append(f"{high} high")
        if medium > 0:
            severity_breakdown_parts.append(f"{medium} medium")
        if low > 0:
            severity_breakdown_parts.append(f"{low} low")
        if info > 0:
            severity_breakdown_parts.append(f"{info} informational")

        severity_text = ", ".join(severity_breakdown_parts) if severity_breakdown_parts else "none"

        top_finding_lines = ""
        if top_findings:
            top_items = []
            for f in top_findings[:5]:
                title = f.get("title", "Unnamed finding")
                sev = f.get("severity", "unknown")
                top_items.append(f'"{title}" ({sev})')
            top_finding_lines = (
                " The most significant findings include: "
                + "; ".join(top_items)
                + "."
            )

        key_findings = (
            f"The findings break down as follows: {severity_text}."
            f"{top_finding_lines}"
        )

        # ---- Risk Posture paragraph ----
        risk_level_display = risk_level.upper()

        trend_text = ""
        if previous_risk_level:
            risk_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            current_val = risk_order.get(risk_level.lower(), 2)
            prev_val = risk_order.get(previous_risk_level.lower(), 2)
            if current_val > prev_val:
                trend_text = (
                    f" This represents an increase in risk from the previous "
                    f"assessment level of {previous_risk_level.upper()}, "
                    f"indicating a deteriorating security posture."
                )
            elif current_val < prev_val:
                trend_text = (
                    f" This represents a decrease from the previous level of "
                    f"{previous_risk_level.upper()}, indicating improvement "
                    f"in the security posture."
                )
            else:
                trend_text = (
                    f" The risk level is unchanged from the previous assessment "
                    f"({previous_risk_level.upper()}), indicating a stable "
                    f"posture."
                )

        affected_pct = (
            round(affected_assets / total_assets * 100) if total_assets > 0 else 0
        )

        risk_posture = (
            f"The overall risk posture is assessed as {risk_level_display}. "
            f"{affected_pct}% of assessed assets ({affected_assets} of "
            f"{total_assets}) have associated findings.{trend_text}"
        )

        # ---- Recommendations paragraph ----
        if recommendations:
            rec_items = [f"  {i+1}. {r}" for i, r in enumerate(recommendations[:5])]
            rec_text = (
                "Based on the assessment results, the following actions are "
                "proposed (in priority order):\n" + "\n".join(rec_items)
            )
        else:
            # Auto-generate recommendations based on data
            auto_recs = []
            if critical > 0:
                auto_recs.append(
                    "Immediately address all critical-severity findings, "
                    "prioritizing those on internet-facing assets."
                )
            if high > 0:
                auto_recs.append(
                    "Remediate high-severity findings within the next "
                    "sprint or maintenance window."
                )
            if medium > 0:
                auto_recs.append(
                    "Plan remediation of medium-severity findings as part "
                    "of the standard vulnerability management cycle."
                )
            if low + info > 0:
                auto_recs.append(
                    "Review low and informational findings for hardening "
                    "opportunities during planned maintenance."
                )
            if not auto_recs:
                auto_recs.append(
                    "Continue regular security assessments to maintain "
                    "the current healthy posture."
                )

            rec_items = [f"  {i+1}. {r}" for i, r in enumerate(auto_recs)]
            rec_text = (
                "Based on the assessment results, the following actions are "
                "proposed (in priority order):\n" + "\n".join(rec_items)
            )

        narrative = (
            f"{exec_summary}\n\n"
            f"{key_findings}\n\n"
            f"{risk_posture}\n\n"
            f"{rec_text}\n\n"
            f"[Note: This narrative was generated by rule-based analysis. "
            f"All statements are derived from the provided assessment data.]"
        )

        logger.info(
            "Narrative generated",
            paragraph_count=4,
            total_findings=total_findings,
        )
        return narrative
