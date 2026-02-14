"""Triage engine for AI Defense Copilot.

Rule-based prioritization of security findings. All results are labeled as
AI Suggestions / Proposed and are evidence-grounded.
"""

import structlog

logger = structlog.get_logger()

# Severity base scores
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 0,
}

# Keywords that indicate a "quick win" (easy fix)
_QUICK_WIN_KEYWORDS: list[str] = [
    "missing header",
    "missing http header",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "server banner",
    "version disclosure",
    "directory listing",
    "default page",
    "unnecessary service",
    "verbose error",
    "http trace",
    "trace method",
    "options method",
]

# Keywords indicating high exploitability
_HIGH_EXPLOIT_KEYWORDS: list[str] = [
    "rce",
    "remote code execution",
    "sql injection",
    "command injection",
    "authentication bypass",
    "unauthenticated",
    "default credential",
    "default password",
    "known exploit",
    "metasploit",
    "proof of concept",
    "poc available",
    "actively exploited",
    "cve-",
    "buffer overflow",
    "deserialization",
    "path traversal",
    "file inclusion",
    "ssrf",
    "xxe",
]

# Keywords for exposure / internet-facing
_EXPOSURE_KEYWORDS: list[str] = [
    "internet-facing",
    "external",
    "public",
    "dmz",
    "exposed",
    "wan",
    "perimeter",
]

# Asset criticality keywords
_CRITICAL_ASSET_KEYWORDS: list[str] = [
    "database",
    "domain controller",
    "active directory",
    "firewall",
    "router",
    "core switch",
    "vpn",
    "certificate authority",
    "ca server",
    "backup",
    "scada",
    "ics",
    "plc",
    "hmi",
    "payment",
    "pci",
    "production",
]


class TriageEngine:
    """Rule-based triage engine for security findings prioritization."""

    def prioritize(self, findings: list[dict]) -> list[dict]:
        """Return findings sorted by priority with rationale.

        Each returned dict is the original finding augmented with:
            - priority_score (int 0-100)
            - priority_rationale (str)
            - recommended_action (str)
            - estimated_effort (str: low/medium/high)
            - ai_label (str): "AI Suggestion - Proposed"

        Args:
            findings: List of finding dicts. Expected keys include
                severity, title, description, exploitability_score,
                asset_criticality, exposure, source_check, category.

        Returns:
            List of augmented finding dicts sorted by priority_score desc.
        """
        logger.info("Triaging findings", count=len(findings))

        prioritized: list[dict] = []
        for finding in findings:
            score, rationale_parts = self._compute_priority(finding)
            effort = self._estimate_effort(finding)
            action = self._recommend_action(finding, score)

            result = dict(finding)
            result["priority_score"] = min(score, 100)
            result["priority_rationale"] = (
                "AI Suggestion: " + "; ".join(rationale_parts)
            )
            result["recommended_action"] = f"Proposed: {action}"
            result["estimated_effort"] = effort
            result["ai_label"] = "AI Suggestion - Proposed"
            prioritized.append(result)

        prioritized.sort(key=lambda f: f["priority_score"], reverse=True)

        logger.info(
            "Triage complete",
            count=len(prioritized),
            top_score=prioritized[0]["priority_score"] if prioritized else 0,
        )
        return prioritized

    def categorize(self, findings: list[dict]) -> dict:
        """Group findings into action categories.

        Returns:
            Dict with keys:
                immediate_action: Critical findings on exposed assets
                short_term: High/medium findings
                long_term: Low risk improvements
                accepted_risk: Info-level or already mitigated
        """
        logger.info("Categorizing findings", count=len(findings))

        prioritized = self.prioritize(findings)

        categories: dict[str, list[dict]] = {
            "immediate_action": [],
            "short_term": [],
            "long_term": [],
            "accepted_risk": [],
        }

        for finding in prioritized:
            severity = finding.get("severity", "info").lower()
            score = finding.get("priority_score", 0)
            is_mitigated = finding.get("mitigated", False)
            is_exposed = self._is_exposed(finding)

            if is_mitigated or severity == "info":
                categories["accepted_risk"].append(finding)
            elif severity == "critical" or (severity == "high" and is_exposed):
                categories["immediate_action"].append(finding)
            elif severity in ("high", "medium") or score >= 40:
                categories["short_term"].append(finding)
            else:
                categories["long_term"].append(finding)

        summary = {k: len(v) for k, v in categories.items()}
        logger.info("Categorization complete", summary=summary)

        return {
            "immediate_action": categories["immediate_action"],
            "short_term": categories["short_term"],
            "long_term": categories["long_term"],
            "accepted_risk": categories["accepted_risk"],
            "summary": summary,
            "ai_label": "AI Suggestion - Proposed categorization",
        }

    # --------------------------------------------------------------------- #
    # Internal scoring helpers
    # --------------------------------------------------------------------- #

    def _compute_priority(self, finding: dict) -> tuple[int, list[str]]:
        """Compute 0-100 priority score with rationale parts."""
        score = 0
        rationale: list[str] = []

        # --- Severity base (0-40) ---
        severity = finding.get("severity", "info").lower()
        sev_score = _SEVERITY_SCORES.get(severity, 0)
        score += sev_score
        rationale.append(
            f"Severity '{severity}' contributes base score of {sev_score}"
        )

        # --- Exploitability (0-20) ---
        exploit_score = self._compute_exploitability(finding)
        score += exploit_score
        if exploit_score > 0:
            rationale.append(
                f"Exploitability adds {exploit_score} points"
            )

        # --- Asset criticality (0-15) ---
        criticality_score = self._compute_asset_criticality(finding)
        score += criticality_score
        if criticality_score > 0:
            rationale.append(
                f"Asset criticality adds {criticality_score} points"
            )

        # --- Exposure level (0-15) ---
        exposure_score = self._compute_exposure(finding)
        score += exposure_score
        if exposure_score > 0:
            rationale.append(
                f"Exposure level adds {exposure_score} points"
            )

        # --- Quick win bonus (+10) ---
        if self._is_quick_win(finding):
            score += 10
            rationale.append(
                "Quick-win bonus (+10): easy fix that improves posture"
            )

        return score, rationale

    def _compute_exploitability(self, finding: dict) -> int:
        """Compute exploitability points (0-20)."""
        # If an explicit exploitability_score is provided, scale it
        explicit = finding.get("exploitability_score")
        if explicit is not None:
            try:
                val = float(explicit)
                # Assume input is 0-10 scale (CVSS-style), map to 0-20
                return min(int(val * 2), 20)
            except (ValueError, TypeError):
                pass

        # Keyword-based heuristic
        text = (
            finding.get("title", "")
            + " "
            + finding.get("description", "")
            + " "
            + finding.get("source_check", "")
        ).lower()

        hits = sum(1 for kw in _HIGH_EXPLOIT_KEYWORDS if kw in text)
        if hits >= 3:
            return 20
        if hits == 2:
            return 15
        if hits == 1:
            return 10
        return 0

    def _compute_asset_criticality(self, finding: dict) -> int:
        """Compute asset criticality points (0-15)."""
        # Explicit criticality field
        crit = finding.get("asset_criticality", "").lower()
        if crit == "critical":
            return 15
        if crit == "high":
            return 12
        if crit == "medium":
            return 8
        if crit == "low":
            return 4

        # Keyword-based on asset info
        text = (
            finding.get("asset_type", "")
            + " "
            + finding.get("hostname", "")
            + " "
            + finding.get("asset_description", "")
        ).lower()

        hits = sum(1 for kw in _CRITICAL_ASSET_KEYWORDS if kw in text)
        if hits >= 2:
            return 15
        if hits == 1:
            return 10
        return 0

    def _compute_exposure(self, finding: dict) -> int:
        """Compute exposure level points (0-15)."""
        # Explicit exposure field
        exposure = finding.get("exposure", "").lower()
        if exposure in ("internet", "external", "public"):
            return 15
        if exposure in ("dmz", "perimeter"):
            return 12
        if exposure in ("internal", "private"):
            return 5

        # Keyword-based
        text = (
            finding.get("zone", "")
            + " "
            + finding.get("description", "")
            + " "
            + finding.get("network", "")
        ).lower()

        hits = sum(1 for kw in _EXPOSURE_KEYWORDS if kw in text)
        if hits >= 2:
            return 15
        if hits == 1:
            return 10
        return 0

    def _is_quick_win(self, finding: dict) -> bool:
        """Determine if a finding is a quick win (easy fix)."""
        text = (
            finding.get("title", "")
            + " "
            + finding.get("description", "")
            + " "
            + finding.get("source_check", "")
        ).lower()

        return any(kw in text for kw in _QUICK_WIN_KEYWORDS)

    def _is_exposed(self, finding: dict) -> bool:
        """Determine if an asset is exposed to external network."""
        exposure = finding.get("exposure", "").lower()
        if exposure in ("internet", "external", "public", "dmz", "perimeter"):
            return True

        text = (
            finding.get("zone", "")
            + " "
            + finding.get("description", "")
        ).lower()

        return any(kw in text for kw in _EXPOSURE_KEYWORDS)

    def _estimate_effort(self, finding: dict) -> str:
        """Estimate remediation effort."""
        if self._is_quick_win(finding):
            return "low"

        severity = finding.get("severity", "info").lower()
        category = finding.get("category", "").lower()

        # Infrastructure changes are generally harder
        hard_categories = ["vuln", "architecture", "design"]
        if category in hard_categories and severity in ("critical", "high"):
            return "high"

        if severity in ("critical", "high"):
            return "medium"

        return "low"

    def _recommend_action(self, finding: dict, score: int) -> str:
        """Generate a recommended first action."""
        severity = finding.get("severity", "info").lower()
        title = finding.get("title", "this finding")
        is_exposed = self._is_exposed(finding)

        if severity == "critical" and is_exposed:
            return (
                f"Immediately isolate or patch the affected asset. "
                f"Finding '{title}' is critical on an exposed asset and "
                f"should be treated as an emergency (score: {score})."
            )
        if severity == "critical":
            return (
                f"Prioritize patching or mitigation for '{title}'. "
                f"Critical severity warrants urgent action (score: {score})."
            )
        if severity == "high" and is_exposed:
            return (
                f"Schedule emergency maintenance for '{title}'. "
                f"High severity on an exposed asset requires prompt "
                f"remediation (score: {score})."
            )
        if severity == "high":
            return (
                f"Add '{title}' to the next maintenance window. "
                f"High severity findings should be resolved within "
                f"one sprint (score: {score})."
            )
        if self._is_quick_win(finding):
            return (
                f"Apply quick fix for '{title}'. This is a low-effort "
                f"improvement that enhances security posture (score: {score})."
            )
        if severity == "medium":
            return (
                f"Plan remediation of '{title}' within the standard "
                f"vulnerability management cycle (score: {score})."
            )
        return (
            f"Review '{title}' during the next hardening review. "
            f"Low priority but contributes to defense-in-depth "
            f"(score: {score})."
        )
