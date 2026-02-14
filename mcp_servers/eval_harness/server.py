"""Eval Harness MCP Server.

Provides mock scenarios for regression testing and quality metrics:
    - list_scenarios: List available test scenarios with optional tag filtering
    - run_scenario: Execute a test scenario and compare expected vs actual results
    - evaluate_consistency: Check scoring consistency across similar findings
    - calculate_metrics: Calculate quality metrics (precision, recall, F1, evidence coverage)
"""

import asyncio
import json
from datetime import datetime

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.eval_harness.scenarios.mock_data import (
    SCENARIOS,
    get_scenario,
    list_scenario_ids,
)
from mcp_servers.eval_harness.metrics import QualityMetrics

logger = structlog.get_logger()

server = BaseMCPServer(name="eval-harness", version="1.0.0")
quality_metrics = QualityMetrics()


# ======================================================================
# Tool 1: list_scenarios
# ======================================================================

@server.tool(
    name="list_scenarios",
    description=(
        "List available test scenarios for regression testing. "
        "Optionally filter by tags. Returns scenario id, name, "
        "description, and tags for each matching scenario."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional list of tags to filter scenarios. "
                    "A scenario matches if it contains ALL specified tags."
                ),
            },
        },
        "required": [],
    },
)
async def list_scenarios(tags: list[str] | None = None) -> dict:
    """List available test scenarios, optionally filtered by tags."""
    logger.info("list_scenarios called", filter_tags=tags)

    results: list[dict] = []
    for scenario in SCENARIOS:
        if tags:
            scenario_tags = set(scenario.get("tags", []))
            if not set(tags).issubset(scenario_tags):
                continue

        results.append({
            "id": scenario["id"],
            "name": scenario["name"],
            "description": scenario["description"],
            "tags": scenario.get("tags", []),
            "finding_count": len(scenario.get("input", {}).get("findings", [])),
            "asset_count": len(
                scenario.get("input", {}).get("assets", [])
                or scenario.get("input", {}).get("baseline", {}).get("assets", [])
            ),
        })

    return ToolResult(
        success=True,
        data={
            "scenarios": results,
            "total": len(results),
            "available_ids": list_scenario_ids(),
        },
        metadata={
            "total_scenarios": len(results),
            "filter_tags": tags,
        },
    ).model_dump()


# ======================================================================
# Tool 2: run_scenario
# ======================================================================

@server.tool(
    name="run_scenario",
    description=(
        "Run a specific test scenario by ID. Returns the scenario input "
        "data alongside expected output so that callers can feed the input "
        "into the risk pipeline and compare actual results against the "
        "expected baseline. If actual_results are provided, an automated "
        "comparison is performed."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "scenario_id": {
                "type": "string",
                "description": "The scenario identifier (e.g. 'basic_router', 'iot_camera').",
            },
            "actual_results": {
                "type": "object",
                "description": (
                    "Optional actual results from a pipeline run to compare "
                    "against expected output. Should contain 'findings' list "
                    "and/or 'risk_levels' list."
                ),
            },
        },
        "required": ["scenario_id"],
    },
)
async def run_scenario(
    scenario_id: str,
    actual_results: dict | None = None,
) -> dict:
    """Run a test scenario and optionally compare against actual results."""
    logger.info("run_scenario called", scenario_id=scenario_id, has_actual=actual_results is not None)

    scenario = get_scenario(scenario_id)
    if scenario is None:
        available = list_scenario_ids()
        return ToolResult(
            success=False,
            error=f"Scenario '{scenario_id}' not found. Available: {available}",
        ).model_dump()

    result_data: dict = {
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "description": scenario["description"],
        "input": scenario["input"],
        "expected_output": scenario["expected_output"],
        "tags": scenario.get("tags", []),
    }

    # Perform automated comparison if actual results are provided
    if actual_results is not None:
        comparison = _compare_results(scenario["expected_output"], actual_results)
        result_data["comparison"] = comparison
        result_data["passed"] = comparison["passed"]
    else:
        result_data["comparison"] = None
        result_data["passed"] = None

    return ToolResult(
        success=True,
        data=result_data,
        artifacts=[{
            "type": "raw_output",
            "tool": "eval_harness",
            "target": scenario_id,
            "content": json.dumps(result_data, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "scenario_id": scenario_id,
            "has_comparison": actual_results is not None,
            "passed": result_data["passed"],
        },
    ).model_dump()


def _compare_results(expected: dict, actual: dict) -> dict:
    """Compare actual pipeline results against expected scenario output."""
    checks: list[dict] = []
    all_passed = True

    # Check finding count
    if "finding_count" in expected:
        actual_count = len(actual.get("findings", []))
        expected_count = expected["finding_count"]
        passed = actual_count == expected_count
        if not passed:
            all_passed = False
        checks.append({
            "check": "finding_count",
            "expected": expected_count,
            "actual": actual_count,
            "passed": passed,
        })

    # Check minimum high/critical count
    if "min_high_critical_count" in expected:
        actual_findings = actual.get("findings", [])
        hc_count = sum(
            1
            for f in actual_findings
            if f.get("severity") in ("high", "critical")
            or f.get("risk_level") in ("high", "critical")
        )
        min_expected = expected["min_high_critical_count"]
        passed = hc_count >= min_expected
        if not passed:
            all_passed = False
        checks.append({
            "check": "min_high_critical_count",
            "expected_min": min_expected,
            "actual": hc_count,
            "passed": passed,
        })

    # Check maximum high/critical count (for false-positive scenarios)
    if "max_high_critical_count" in expected:
        actual_findings = actual.get("findings", [])
        hc_count = sum(
            1
            for f in actual_findings
            if f.get("severity") in ("high", "critical")
            or f.get("risk_level") in ("high", "critical")
        )
        max_expected = expected["max_high_critical_count"]
        passed = hc_count <= max_expected
        if not passed:
            all_passed = False
        checks.append({
            "check": "max_high_critical_count",
            "expected_max": max_expected,
            "actual": hc_count,
            "passed": passed,
        })

    # Check required MITRE IDs
    if "required_mitre_ids" in expected and expected["required_mitre_ids"]:
        actual_mitre = set(actual.get("mitre_ids", []))
        required = set(expected["required_mitre_ids"])
        missing = required - actual_mitre
        passed = len(missing) == 0
        if not passed:
            all_passed = False
        checks.append({
            "check": "required_mitre_ids",
            "expected": sorted(required),
            "actual": sorted(actual_mitre),
            "missing": sorted(missing),
            "passed": passed,
        })

    # Check risk levels present
    if "risk_levels_present" in expected:
        actual_levels = set(actual.get("risk_levels", []))
        expected_levels = set(expected["risk_levels_present"])
        missing_levels = expected_levels - actual_levels
        passed = len(missing_levels) == 0
        if not passed:
            all_passed = False
        checks.append({
            "check": "risk_levels_present",
            "expected": sorted(expected_levels),
            "actual": sorted(actual_levels),
            "missing": sorted(missing_levels),
            "passed": passed,
        })

    # Check new asset count for drift scenarios
    if "new_asset_count" in expected:
        actual_new = actual.get("new_asset_count", 0)
        expected_new = expected["new_asset_count"]
        passed = actual_new == expected_new
        if not passed:
            all_passed = False
        checks.append({
            "check": "new_asset_count",
            "expected": expected_new,
            "actual": actual_new,
            "passed": passed,
        })

    # Check total drift alerts
    if "total_drift_alerts" in expected:
        actual_alerts = actual.get("total_drift_alerts", 0)
        expected_alerts = expected["total_drift_alerts"]
        passed = actual_alerts == expected_alerts
        if not passed:
            all_passed = False
        checks.append({
            "check": "total_drift_alerts",
            "expected": expected_alerts,
            "actual": actual_alerts,
            "passed": passed,
        })

    return {
        "passed": all_passed,
        "checks": checks,
        "total_checks": len(checks),
        "passed_checks": sum(1 for c in checks if c["passed"]),
        "failed_checks": sum(1 for c in checks if not c["passed"]),
    }


# ======================================================================
# Tool 3: evaluate_consistency
# ======================================================================

@server.tool(
    name="evaluate_consistency",
    description=(
        "Check whether scoring is consistent across similar findings. "
        "Finds groups of findings with the same source_check and verifies "
        "they received the same severity rating. Also checks the "
        "no-claim-without-evidence principle and evidence chain integrity."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "List of findings to evaluate. Each finding should have "
                    "id, title, severity, source_check, source_tool, evidence, "
                    "and asset_ip fields."
                ),
            },
            "artifacts": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "Optional list of evidence artifacts. Each artifact should "
                    "have target (asset IP) and tool (source tool) fields. "
                    "Used for evidence chain verification."
                ),
            },
        },
        "required": ["findings"],
    },
)
async def evaluate_consistency(
    findings: list[dict],
    artifacts: list[dict] | None = None,
) -> dict:
    """Evaluate scoring consistency and evidence compliance."""
    logger.info(
        "evaluate_consistency called",
        finding_count=len(findings),
        artifact_count=len(artifacts) if artifacts else 0,
    )

    # Score consistency check
    consistency = quality_metrics.check_score_consistency(findings)

    # No-claim-without-evidence compliance
    evidence_compliance = quality_metrics.evaluate_no_claim_without_evidence(findings)

    # Evidence chain verification (only if artifacts provided)
    evidence_chain: dict | None = None
    if artifacts is not None:
        evidence_chain = quality_metrics.verify_evidence_chain(findings, artifacts)

    result_data = {
        "consistency": consistency,
        "evidence_compliance": evidence_compliance,
        "evidence_chain": evidence_chain,
        "summary": {
            "consistency_score": consistency["consistency_score"],
            "evidence_compliance_rate": evidence_compliance["compliance_rate"],
            "evidence_coverage_rate": (
                evidence_chain["coverage_rate"] if evidence_chain else None
            ),
            "total_findings_evaluated": len(findings),
        },
    }

    return ToolResult(
        success=True,
        data=result_data,
        artifacts=[{
            "type": "raw_output",
            "tool": "eval_harness",
            "target": "consistency_check",
            "content": json.dumps(result_data["summary"], indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "consistency_score": consistency["consistency_score"],
            "compliance_rate": evidence_compliance["compliance_rate"],
            "finding_count": len(findings),
        },
    ).model_dump()


# ======================================================================
# Tool 4: calculate_metrics
# ======================================================================

@server.tool(
    name="calculate_metrics",
    description=(
        "Calculate quality metrics for pipeline output: true positives, "
        "false positives, false negatives, precision, recall, and F1 score. "
        "Compares actual findings against expected findings using finding IDs. "
        "Optionally also evaluates evidence chain coverage."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "expected_findings": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "List of expected findings (ground truth). Each must have "
                    "an 'id' field for matching."
                ),
            },
            "actual_findings": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "List of actual findings produced by the pipeline. "
                    "Each must have an 'id' field for matching."
                ),
            },
            "artifacts": {
                "type": "array",
                "items": {"type": "object"},
                "description": (
                    "Optional list of evidence artifacts for coverage analysis. "
                    "Each should have 'target' and 'tool' fields."
                ),
            },
        },
        "required": ["expected_findings", "actual_findings"],
    },
)
async def calculate_metrics(
    expected_findings: list[dict],
    actual_findings: list[dict],
    artifacts: list[dict] | None = None,
) -> dict:
    """Calculate classification and quality metrics."""
    logger.info(
        "calculate_metrics called",
        expected_count=len(expected_findings),
        actual_count=len(actual_findings),
        artifact_count=len(artifacts) if artifacts else 0,
    )

    # Core classification metrics
    classification = quality_metrics.calculate(expected_findings, actual_findings)

    # Evidence compliance on actual findings
    evidence_compliance = quality_metrics.evaluate_no_claim_without_evidence(
        actual_findings
    )

    # Evidence chain coverage (if artifacts provided)
    evidence_chain: dict | None = None
    if artifacts is not None:
        evidence_chain = quality_metrics.verify_evidence_chain(
            actual_findings, artifacts
        )

    # Severity breakdown for actual findings
    severity_counts: dict[str, int] = {}
    for f in actual_findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    result_data = {
        "classification": classification,
        "evidence_compliance": evidence_compliance,
        "evidence_chain": evidence_chain,
        "severity_distribution": severity_counts,
        "summary": {
            "precision": classification["precision"],
            "recall": classification["recall"],
            "f1_score": classification["f1_score"],
            "true_positives": classification["true_positives"],
            "false_positives": classification["false_positives"],
            "false_negatives": classification["false_negatives"],
            "evidence_compliance_rate": evidence_compliance["compliance_rate"],
            "evidence_coverage_rate": (
                evidence_chain["coverage_rate"] if evidence_chain else None
            ),
        },
    }

    return ToolResult(
        success=True,
        data=result_data,
        artifacts=[{
            "type": "raw_output",
            "tool": "eval_harness",
            "target": "quality_metrics",
            "content": json.dumps(result_data["summary"], indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "precision": classification["precision"],
            "recall": classification["recall"],
            "f1_score": classification["f1_score"],
            "expected_count": len(expected_findings),
            "actual_count": len(actual_findings),
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
