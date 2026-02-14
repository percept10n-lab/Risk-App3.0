import hashlib
from datetime import datetime
import structlog

logger = structlog.get_logger()


class FindingNormalizer:
    """Normalizes and deduplicates findings from various vulnerability checks."""

    def normalize(self, finding: dict, source_tool: str, target: str) -> dict:
        """Normalize a single finding to the standard schema."""
        return {
            "title": finding.get("title", "Unknown finding"),
            "description": finding.get("description", ""),
            "severity": self._normalize_severity(finding.get("severity", "info")),
            "category": finding.get("category", "info"),
            "source_tool": source_tool,
            "source_check": finding.get("source_check", source_tool),
            "target": target,
            "cve_ids": finding.get("cve_ids", []),
            "cwe_id": finding.get("cwe_id"),
            "cpe": finding.get("cpe"),
            "evidence": finding.get("evidence", ""),
            "remediation": finding.get("remediation"),
            "raw_output_snippet": finding.get("evidence", ""),
            "dedupe_hash": self._compute_dedupe_hash(
                target, source_tool,
                finding.get("source_check", source_tool),
                finding.get("title", ""),
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def normalize_batch(self, findings: list[dict], source_tool: str, target: str) -> list[dict]:
        """Normalize a batch of findings."""
        return [self.normalize(f, source_tool, target) for f in findings]

    def deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings based on dedupe_hash."""
        seen = set()
        unique = []
        for finding in findings:
            h = finding.get("dedupe_hash", "")
            if h and h not in seen:
                seen.add(h)
                unique.append(finding)
            elif not h:
                unique.append(finding)
        return unique

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize severity string to standard values."""
        severity = severity.lower().strip()
        mapping = {
            "info": "info",
            "informational": "info",
            "information": "info",
            "low": "low",
            "medium": "medium",
            "moderate": "medium",
            "high": "high",
            "critical": "critical",
            "severe": "critical",
        }
        return mapping.get(severity, "info")

    @staticmethod
    def _compute_dedupe_hash(target: str, source_tool: str, source_check: str, title: str) -> str:
        """Compute deduplication hash."""
        content = f"{target}:{source_tool}:{source_check}:{title}"
        return hashlib.sha256(content.encode()).hexdigest()
