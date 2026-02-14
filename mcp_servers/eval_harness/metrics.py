"""Quality metrics for evaluating risk-assessment pipeline outputs.

Provides standard ML evaluation metrics (precision, recall, F1), scoring
consistency checks, evidence chain verification, and the
"no claim without evidence" compliance audit.
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger()


class QualityMetrics:
    """Calculate quality and consistency metrics for pipeline outputs."""

    # Severity levels in ascending order for comparison
    _SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    # ------------------------------------------------------------------ #
    # Core classification metrics
    # ------------------------------------------------------------------ #

    def calculate(
        self,
        expected: list[dict],
        actual: list[dict],
    ) -> dict:
        """Calculate classification quality metrics.

        Each item in *expected* and *actual* must contain at least an ``id``
        field.  When a matching ``id`` exists in both lists the item is a
        true positive.  Items only in *actual* are false positives, and items
        only in *expected* are false negatives.

        Returns a dict with ``true_positives``, ``false_positives``,
        ``false_negatives``, ``precision``, ``recall``, and ``f1_score``.
        """
        logger.info(
            "calculate metrics",
            expected_count=len(expected),
            actual_count=len(actual),
        )

        expected_ids = {item["id"] for item in expected if "id" in item}
        actual_ids = {item["id"] for item in actual if "id" in item}

        tp_ids = expected_ids & actual_ids
        fp_ids = actual_ids - expected_ids
        fn_ids = expected_ids - actual_ids

        true_positives = len(tp_ids)
        false_positives = len(fp_ids)
        false_negatives = len(fn_ids)

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )
        f1_score = (
            2.0 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        result = {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_positive_ids": sorted(tp_ids),
            "false_positive_ids": sorted(fp_ids),
            "false_negative_ids": sorted(fn_ids),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
        }

        logger.info(
            "metrics calculated",
            tp=true_positives,
            fp=false_positives,
            fn=false_negatives,
            precision=result["precision"],
            recall=result["recall"],
            f1=result["f1_score"],
        )
        return result

    # ------------------------------------------------------------------ #
    # Scoring consistency
    # ------------------------------------------------------------------ #

    def check_score_consistency(self, findings: list[dict]) -> dict:
        """Check whether similar findings receive consistent severity scores.

        Two findings are deemed *similar* when they share the same
        ``source_check`` value.  For each group of similar findings the
        method verifies that all members carry the same ``severity``.

        Returns a dict with ``consistency_score`` (0.0 -- 1.0) and a list of
        ``inconsistencies`` describing any discrepancies.
        """
        logger.info("check_score_consistency", finding_count=len(findings))

        # Group findings by source_check
        groups: dict[str, list[dict]] = {}
        for finding in findings:
            key = finding.get("source_check", "unknown")
            groups.setdefault(key, []).append(finding)

        total_groups = 0
        consistent_groups = 0
        inconsistencies: list[dict] = []

        for check_name, group_findings in groups.items():
            if len(group_findings) < 2:
                # A single finding cannot be inconsistent with itself
                continue

            total_groups += 1
            severities = {f.get("severity", "unknown") for f in group_findings}

            if len(severities) == 1:
                consistent_groups += 1
            else:
                # Collect details about the inconsistency
                details: list[dict] = []
                for f in group_findings:
                    details.append({
                        "id": f.get("id", "unknown"),
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "unknown"),
                        "asset_ip": f.get("asset_ip", "unknown"),
                    })

                inconsistencies.append({
                    "source_check": check_name,
                    "severities_found": sorted(severities),
                    "finding_count": len(group_findings),
                    "findings": details,
                })

        consistency_score = (
            consistent_groups / total_groups
            if total_groups > 0
            else 1.0  # No comparable groups means nothing to be inconsistent
        )

        result = {
            "consistency_score": round(consistency_score, 4),
            "total_comparable_groups": total_groups,
            "consistent_groups": consistent_groups,
            "inconsistencies": inconsistencies,
        }

        logger.info(
            "consistency check complete",
            score=result["consistency_score"],
            inconsistency_count=len(inconsistencies),
        )
        return result

    # ------------------------------------------------------------------ #
    # Evidence chain verification
    # ------------------------------------------------------------------ #

    def verify_evidence_chain(
        self,
        findings: list[dict],
        artifacts: list[dict],
    ) -> dict:
        """Verify that every finding references valid supporting evidence.

        A finding is *covered* when at least one artifact's ``target``
        matches the finding's ``asset_ip`` **and** the artifact's ``tool``
        matches the finding's ``source_tool``.

        Returns ``coverage_rate`` (0.0 -- 1.0) and ``orphaned_findings``
        (findings with no matching artifact).
        """
        logger.info(
            "verify_evidence_chain",
            finding_count=len(findings),
            artifact_count=len(artifacts),
        )

        # Build a set of (target, tool) tuples from artifacts for fast lookup
        artifact_keys: set[tuple[str, str]] = set()
        for artifact in artifacts:
            target = artifact.get("target", "")
            tool = artifact.get("tool", "")
            if target and tool:
                artifact_keys.add((target, tool))

        covered_count = 0
        orphaned_findings: list[dict] = []

        for finding in findings:
            asset_ip = finding.get("asset_ip", "")
            source_tool = finding.get("source_tool", "")
            finding_key = (asset_ip, source_tool)

            if finding_key in artifact_keys:
                covered_count += 1
            else:
                orphaned_findings.append({
                    "id": finding.get("id", "unknown"),
                    "title": finding.get("title", ""),
                    "asset_ip": asset_ip,
                    "source_tool": source_tool,
                    "reason": "No matching artifact found for (asset_ip, source_tool) pair.",
                })

        total = len(findings)
        coverage_rate = covered_count / total if total > 0 else 1.0

        result = {
            "coverage_rate": round(coverage_rate, 4),
            "total_findings": total,
            "covered_findings": covered_count,
            "orphaned_findings": orphaned_findings,
        }

        logger.info(
            "evidence chain verified",
            coverage_rate=result["coverage_rate"],
            orphaned_count=len(orphaned_findings),
        )
        return result

    # ------------------------------------------------------------------ #
    # No-claim-without-evidence audit
    # ------------------------------------------------------------------ #

    def evaluate_no_claim_without_evidence(self, findings: list[dict]) -> dict:
        """Verify the 'no claim without evidence' principle.

        Every finding **must** have non-empty values for:
            - ``evidence``
            - ``source_tool``
            - ``source_check``

        Returns ``compliance_rate`` (0.0 -- 1.0) and ``violations`` listing
        each non-compliant finding with the missing fields.
        """
        logger.info(
            "evaluate_no_claim_without_evidence",
            finding_count=len(findings),
        )

        required_fields = ["evidence", "source_tool", "source_check"]
        violations: list[dict] = []
        compliant_count = 0

        for finding in findings:
            missing: list[str] = []
            for field in required_fields:
                value = finding.get(field)
                if not value or (isinstance(value, str) and not value.strip()):
                    missing.append(field)

            if missing:
                violations.append({
                    "id": finding.get("id", "unknown"),
                    "title": finding.get("title", ""),
                    "missing_fields": missing,
                })
            else:
                compliant_count += 1

        total = len(findings)
        compliance_rate = compliant_count / total if total > 0 else 1.0

        result = {
            "compliance_rate": round(compliance_rate, 4),
            "total_findings": total,
            "compliant_findings": compliant_count,
            "violations": violations,
        }

        logger.info(
            "no-claim-without-evidence evaluated",
            compliance_rate=result["compliance_rate"],
            violation_count=len(violations),
        )
        return result
