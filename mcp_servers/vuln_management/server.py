"""Vulnerability Management MCP Server.

Manages the vulnerability lifecycle, SLA tracking, and trend metrics.

Provides six tools:
    - create_vuln_item: Create a vulnerability tracking item from a finding
    - update_status: Update vulnerability status with transition validation
    - batch_create: Batch-create vuln items from findings with deduplication
    - calculate_sla: Calculate SLA deadline based on severity
    - get_metrics: Calculate vulnerability metrics from a list of vuln items
    - get_sla_breaches: Identify SLA-breached or at-risk vulnerabilities
"""
import asyncio
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult

logger = structlog.get_logger()

server = BaseMCPServer(name="vuln-management", version="1.0.0")


# ======================================================================
# SLA definitions (hours)
# ======================================================================

SLA_HOURS: dict[str, int | None] = {
    "critical": 24,
    "high": 168,       # 7 days
    "medium": 720,     # 30 days
    "low": 2160,       # 90 days
    "info": None,       # no SLA
}

# ======================================================================
# Valid status transitions
# ======================================================================

VALID_TRANSITIONS: dict[str, list[str]] = {
    "open": ["in_progress", "accepted", "exception"],
    "in_progress": ["fixed", "open"],
    "fixed": ["verified", "open"],
    "accepted": ["open"],
    "exception": ["open"],
    "verified": [],
}


class VulnLifecycleManager:
    """Manages the vulnerability lifecycle: creation, status transitions,
    SLA calculation, metrics computation, and history tracking."""

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_item(self, finding: dict) -> dict:
        """Create a vulnerability tracking item from a finding dict.

        Args:
            finding: dict with keys id, title, severity, asset_id (at minimum).

        Returns:
            A fully-populated vuln item dict.
        """
        now = datetime.utcnow()
        now_iso = now.isoformat() + "Z"
        severity = finding.get("severity", "medium").lower()
        vuln_id = f"VULN-{uuid.uuid4().hex[:12].upper()}"

        sla_info = self.compute_sla(severity, now_iso)

        item: dict = {
            "vuln_id": vuln_id,
            "finding_id": finding.get("id", ""),
            "title": finding.get("title", "Untitled Finding"),
            "severity": severity,
            "asset_id": finding.get("asset_id", ""),
            "status": "open",
            "created_at": now_iso,
            "updated_at": now_iso,
            "sla_deadline": sla_info["deadline"],
            "sla_hours": sla_info["sla_hours"],
            "remaining_days": sla_info["remaining_days"],
            "assigned_to": None,
            "comments": [],
            "history": [
                {
                    "timestamp": now_iso,
                    "action": "created",
                    "from_status": None,
                    "to_status": "open",
                    "comment": "Vulnerability item created from finding.",
                }
            ],
        }

        logger.info(
            "vuln_item_created",
            vuln_id=vuln_id,
            finding_id=finding.get("id"),
            severity=severity,
            sla_deadline=sla_info["deadline"],
        )
        return item

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def update_status(self, item: dict, new_status: str, comment: str = "") -> dict:
        """Transition a vuln item to a new status with validation.

        Args:
            item: The existing vuln item dict.
            new_status: Target status string.
            comment: Optional comment describing the transition.

        Returns:
            The updated vuln item dict.

        Raises:
            ValueError: If the transition is not allowed.
        """
        current_status = item.get("status", "open")
        allowed = VALID_TRANSITIONS.get(current_status, [])

        if new_status not in allowed:
            raise ValueError(
                f"Invalid status transition: '{current_status}' -> '{new_status}'. "
                f"Allowed transitions from '{current_status}': {allowed}"
            )

        now_iso = datetime.utcnow().isoformat() + "Z"

        item["status"] = new_status
        item["updated_at"] = now_iso

        # If transitioning to fixed, record the fixed_at timestamp
        if new_status == "fixed":
            item["fixed_at"] = now_iso

        # If reopening from fixed, clear fixed_at
        if current_status == "fixed" and new_status == "open":
            item.pop("fixed_at", None)

        # Append to history
        history_entry = {
            "timestamp": now_iso,
            "action": "status_change",
            "from_status": current_status,
            "to_status": new_status,
            "comment": comment,
        }
        item.setdefault("history", []).append(history_entry)

        # Append comment if provided
        if comment:
            item.setdefault("comments", []).append({
                "timestamp": now_iso,
                "text": comment,
                "action": f"status_change: {current_status} -> {new_status}",
            })

        logger.info(
            "vuln_status_updated",
            vuln_id=item.get("vuln_id"),
            from_status=current_status,
            to_status=new_status,
        )
        return item

    # ------------------------------------------------------------------
    # SLA calculation
    # ------------------------------------------------------------------

    def compute_sla(self, severity: str, created_at: str) -> dict:
        """Calculate SLA deadline and remaining time.

        Args:
            severity: One of critical, high, medium, low, info.
            created_at: ISO 8601 timestamp of creation.

        Returns:
            dict with deadline, sla_hours, remaining_days, remaining_hours, is_breached.
        """
        severity = severity.lower()
        sla_hours = SLA_HOURS.get(severity)

        if sla_hours is None:
            return {
                "severity": severity,
                "sla_hours": None,
                "deadline": None,
                "remaining_days": None,
                "remaining_hours": None,
                "is_breached": False,
            }

        # Parse created_at — strip trailing Z for fromisoformat compatibility
        created_str = created_at.rstrip("Z")
        created_dt = datetime.fromisoformat(created_str)
        deadline_dt = created_dt + timedelta(hours=sla_hours)
        deadline_iso = deadline_dt.isoformat() + "Z"

        now = datetime.utcnow()
        remaining = deadline_dt - now
        remaining_total_seconds = remaining.total_seconds()
        remaining_hours = remaining_total_seconds / 3600.0
        remaining_days = remaining_total_seconds / 86400.0
        is_breached = remaining_total_seconds < 0

        return {
            "severity": severity,
            "sla_hours": sla_hours,
            "deadline": deadline_iso,
            "remaining_days": round(remaining_days, 2),
            "remaining_hours": round(remaining_hours, 2),
            "is_breached": is_breached,
        }

    # ------------------------------------------------------------------
    # Batch creation with deduplication
    # ------------------------------------------------------------------

    def batch_create(self, findings: list[dict]) -> dict:
        """Create vuln items from a list of findings, deduplicating by finding_id.

        Args:
            findings: List of finding dicts.

        Returns:
            Summary dict with created items, duplicates skipped, and counts.
        """
        seen_ids: set[str] = set()
        created_items: list[dict] = []
        duplicates: list[str] = []

        for finding in findings:
            finding_id = finding.get("id", "")
            if finding_id and finding_id in seen_ids:
                duplicates.append(finding_id)
                continue
            if finding_id:
                seen_ids.add(finding_id)

            item = self.create_item(finding)
            created_items.append(item)

        logger.info(
            "batch_create_completed",
            total_findings=len(findings),
            created=len(created_items),
            duplicates_skipped=len(duplicates),
        )

        return {
            "created_items": created_items,
            "total_submitted": len(findings),
            "total_created": len(created_items),
            "duplicates_skipped": len(duplicates),
            "duplicate_finding_ids": duplicates,
        }

    # ------------------------------------------------------------------
    # Metrics computation
    # ------------------------------------------------------------------

    def compute_metrics(self, items: list[dict]) -> dict:
        """Calculate comprehensive vulnerability metrics.

        Args:
            items: List of vuln item dicts.

        Returns:
            dict with counts, MTTR, SLA compliance, severity distribution,
            aging analysis, and trend data.
        """
        now = datetime.utcnow()

        # --- Status counts ---
        status_counts = {
            "total": len(items),
            "open": 0,
            "in_progress": 0,
            "fixed": 0,
            "accepted": 0,
            "exception": 0,
            "verified": 0,
        }
        for item in items:
            status = item.get("status", "open")
            if status in status_counts:
                status_counts[status] += 1

        # --- Mean Time to Remediate (MTTR) ---
        remediation_times: list[float] = []
        for item in items:
            if item.get("status") in ("fixed", "verified") and item.get("fixed_at"):
                created_str = item["created_at"].rstrip("Z")
                fixed_str = item["fixed_at"].rstrip("Z")
                created_dt = datetime.fromisoformat(created_str)
                fixed_dt = datetime.fromisoformat(fixed_str)
                delta_hours = (fixed_dt - created_dt).total_seconds() / 3600.0
                remediation_times.append(delta_hours)

        mttr_hours = (
            round(sum(remediation_times) / len(remediation_times), 2)
            if remediation_times
            else None
        )
        mttr_days = round(mttr_hours / 24.0, 2) if mttr_hours is not None else None

        # --- SLA compliance rate ---
        sla_eligible = 0
        sla_met = 0
        for item in items:
            if item.get("status") in ("fixed", "verified") and item.get("sla_deadline"):
                sla_eligible += 1
                fixed_str = item.get("fixed_at", "").rstrip("Z")
                deadline_str = item["sla_deadline"].rstrip("Z")
                if fixed_str:
                    fixed_dt = datetime.fromisoformat(fixed_str)
                    deadline_dt = datetime.fromisoformat(deadline_str)
                    if fixed_dt <= deadline_dt:
                        sla_met += 1

        sla_compliance_rate = (
            round((sla_met / sla_eligible) * 100.0, 2)
            if sla_eligible > 0
            else None
        )

        # --- Severity distribution ---
        severity_distribution: dict[str, int] = defaultdict(int)
        for item in items:
            sev = item.get("severity", "unknown").lower()
            severity_distribution[sev] += 1

        # --- Aging analysis (based on open/in_progress items) ---
        aging = {"0-7d": 0, "7-30d": 0, "30-90d": 0, "90+d": 0}
        for item in items:
            if item.get("status") in ("open", "in_progress"):
                created_str = item.get("created_at", "").rstrip("Z")
                if created_str:
                    created_dt = datetime.fromisoformat(created_str)
                    age_days = (now - created_dt).total_seconds() / 86400.0
                    if age_days <= 7:
                        aging["0-7d"] += 1
                    elif age_days <= 30:
                        aging["7-30d"] += 1
                    elif age_days <= 90:
                        aging["30-90d"] += 1
                    else:
                        aging["90+d"] += 1

        # --- Trend data (items created per week for last 12 weeks) ---
        trend: list[dict] = []
        for weeks_ago in range(11, -1, -1):
            week_start = now - timedelta(weeks=weeks_ago + 1)
            week_end = now - timedelta(weeks=weeks_ago)
            count = 0
            for item in items:
                created_str = item.get("created_at", "").rstrip("Z")
                if created_str:
                    created_dt = datetime.fromisoformat(created_str)
                    if week_start <= created_dt < week_end:
                        count += 1
            trend.append({
                "week_start": week_start.strftime("%Y-%m-%d"),
                "week_end": week_end.strftime("%Y-%m-%d"),
                "count": count,
            })

        return {
            "status_counts": status_counts,
            "mttr_hours": mttr_hours,
            "mttr_days": mttr_days,
            "sla_compliance_rate": sla_compliance_rate,
            "sla_eligible_count": sla_eligible,
            "sla_met_count": sla_met,
            "severity_distribution": dict(severity_distribution),
            "aging_analysis": aging,
            "trend_data": trend,
        }

    # ------------------------------------------------------------------
    # SLA breach detection
    # ------------------------------------------------------------------

    def get_sla_breaches(self, items: list[dict]) -> list[dict]:
        """Identify vuln items that have breached or are about to breach SLA.

        Only considers items in open or in_progress status. Items are sorted
        by urgency: breached first (most overdue first), then at-risk
        (least remaining time first).

        Args:
            items: List of vuln item dicts.

        Returns:
            List of dicts describing each breached or at-risk item.
        """
        now = datetime.utcnow()
        at_risk_threshold_hours = 48  # warn if within 48 hours of deadline

        results: list[dict] = []

        for item in items:
            status = item.get("status", "")
            if status not in ("open", "in_progress"):
                continue

            deadline_str = item.get("sla_deadline")
            if not deadline_str:
                continue  # info severity or no deadline

            deadline_dt = datetime.fromisoformat(deadline_str.rstrip("Z"))
            remaining = deadline_dt - now
            remaining_hours = remaining.total_seconds() / 3600.0
            remaining_days = remaining.total_seconds() / 86400.0
            is_breached = remaining_hours < 0

            if is_breached or remaining_hours <= at_risk_threshold_hours:
                results.append({
                    "vuln_id": item.get("vuln_id", ""),
                    "finding_id": item.get("finding_id", ""),
                    "title": item.get("title", ""),
                    "severity": item.get("severity", ""),
                    "asset_id": item.get("asset_id", ""),
                    "status": status,
                    "created_at": item.get("created_at", ""),
                    "sla_deadline": deadline_str,
                    "remaining_hours": round(remaining_hours, 2),
                    "remaining_days": round(remaining_days, 2),
                    "is_breached": is_breached,
                    "breach_category": "breached" if is_breached else "at_risk",
                    "overdue_hours": round(abs(remaining_hours), 2) if is_breached else 0,
                })

        # Sort: breached first (most overdue), then at-risk (least remaining)
        results.sort(key=lambda r: r["remaining_hours"])

        logger.info(
            "sla_breach_check_completed",
            total_checked=len(items),
            breached=sum(1 for r in results if r["is_breached"]),
            at_risk=sum(1 for r in results if not r["is_breached"]),
        )

        return results


# Instantiate the lifecycle manager
lifecycle = VulnLifecycleManager()


# ======================================================================
# Tool 1: create_vuln_item
# ======================================================================

@server.tool(
    name="create_vuln_item",
    description=(
        "Create a vulnerability tracking item from a finding. "
        "Auto-calculates SLA deadline based on severity. "
        "Returns the created vuln item with vuln_id, status, SLA info, and history."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "finding": {
                "type": "object",
                "description": "Finding dict with id, title, severity, and asset_id",
                "properties": {
                    "id": {"type": "string", "description": "Unique finding identifier"},
                    "title": {"type": "string", "description": "Finding title"},
                    "severity": {
                        "type": "string",
                        "description": "Severity level",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "asset_id": {"type": "string", "description": "Associated asset identifier"},
                },
                "required": ["id", "title", "severity", "asset_id"],
            },
        },
        "required": ["finding"],
    },
)
async def create_vuln_item(finding: dict) -> dict:
    """Create a vulnerability tracking item from a finding."""
    logger.info(
        "create_vuln_item called",
        finding_id=finding.get("id"),
        severity=finding.get("severity"),
    )

    item = lifecycle.create_item(finding)

    return ToolResult(
        success=True,
        data=item,
        artifacts=[{
            "type": "raw_output",
            "tool": "vuln_management",
            "target": item["vuln_id"],
            "content": json.dumps(item, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "vuln_id": item["vuln_id"],
            "severity": item["severity"],
            "sla_deadline": item["sla_deadline"],
        },
    ).model_dump()


# ======================================================================
# Tool 2: update_status
# ======================================================================

@server.tool(
    name="update_status",
    description=(
        "Update vulnerability status with enforced transition validation. "
        "Valid transitions: open->in_progress, open->accepted, open->exception, "
        "in_progress->fixed, in_progress->open (reopen), fixed->verified, "
        "fixed->open (reopen), accepted->open, exception->open. "
        "Returns the updated vuln item with history appended."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "vuln_item": {
                "type": "object",
                "description": "The existing vulnerability item to update",
            },
            "new_status": {
                "type": "string",
                "description": "Target status",
                "enum": ["open", "in_progress", "fixed", "verified", "accepted", "exception"],
            },
            "comment": {
                "type": "string",
                "description": "Comment explaining the status change",
                "default": "",
            },
        },
        "required": ["vuln_item", "new_status"],
    },
)
async def update_status(vuln_item: dict, new_status: str, comment: str = "") -> dict:
    """Update vulnerability status with transition validation."""
    logger.info(
        "update_status called",
        vuln_id=vuln_item.get("vuln_id"),
        current_status=vuln_item.get("status"),
        new_status=new_status,
    )

    try:
        updated = lifecycle.update_status(vuln_item, new_status, comment)
        return ToolResult(
            success=True,
            data=updated,
            artifacts=[{
                "type": "raw_output",
                "tool": "vuln_management",
                "target": updated.get("vuln_id", "unknown"),
                "content": json.dumps(updated, indent=2),
                "timestamp": datetime.utcnow().isoformat(),
            }],
            metadata={
                "vuln_id": updated.get("vuln_id"),
                "previous_status": vuln_item.get("status"),
                "new_status": new_status,
            },
        ).model_dump()
    except ValueError as e:
        logger.warning(
            "invalid_status_transition",
            vuln_id=vuln_item.get("vuln_id"),
            error=str(e),
        )
        return ToolResult(
            success=False,
            error=str(e),
            metadata={
                "vuln_id": vuln_item.get("vuln_id"),
                "current_status": vuln_item.get("status"),
                "requested_status": new_status,
            },
        ).model_dump()


# ======================================================================
# Tool 3: batch_create
# ======================================================================

@server.tool(
    name="batch_create",
    description=(
        "Create vulnerability tracking items from a list of findings. "
        "Deduplicates by finding_id so the same finding is not tracked twice. "
        "Returns a summary with created items, counts, and duplicate info."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of finding dicts, each with id, title, severity, asset_id",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                        "asset_id": {"type": "string"},
                    },
                    "required": ["id", "title", "severity", "asset_id"],
                },
            },
        },
        "required": ["findings"],
    },
)
async def batch_create(findings: list[dict]) -> dict:
    """Batch-create vuln items from findings with deduplication."""
    logger.info("batch_create called", finding_count=len(findings))

    result = lifecycle.batch_create(findings)

    return ToolResult(
        success=True,
        data=result,
        artifacts=[{
            "type": "raw_output",
            "tool": "vuln_management_batch",
            "target": "batch",
            "content": json.dumps({
                "total_submitted": result["total_submitted"],
                "total_created": result["total_created"],
                "duplicates_skipped": result["duplicates_skipped"],
            }, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "total_submitted": result["total_submitted"],
            "total_created": result["total_created"],
            "duplicates_skipped": result["duplicates_skipped"],
        },
    ).model_dump()


# ======================================================================
# Tool 4: calculate_sla
# ======================================================================

@server.tool(
    name="calculate_sla",
    description=(
        "Calculate SLA deadline based on severity and creation time. "
        "SLA windows: critical=24h, high=7d, medium=30d, low=90d, info=no SLA. "
        "Returns the deadline date in ISO 8601 and remaining days/hours."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "description": "Vulnerability severity level",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "created_at": {
                "type": "string",
                "description": "Creation timestamp in ISO 8601 format (e.g. 2025-01-15T10:30:00Z)",
            },
        },
        "required": ["severity", "created_at"],
    },
)
async def calculate_sla(severity: str, created_at: str) -> dict:
    """Calculate SLA deadline based on severity."""
    logger.info("calculate_sla called", severity=severity, created_at=created_at)

    sla_info = lifecycle.compute_sla(severity, created_at)

    return ToolResult(
        success=True,
        data=sla_info,
        metadata={
            "severity": severity,
            "sla_hours": sla_info["sla_hours"],
            "deadline": sla_info["deadline"],
            "is_breached": sla_info["is_breached"],
        },
    ).model_dump()


# ======================================================================
# Tool 5: get_metrics
# ======================================================================

@server.tool(
    name="get_metrics",
    description=(
        "Calculate comprehensive vulnerability metrics from a list of vuln items. "
        "Returns status counts (total, open, in_progress, fixed, accepted, exception, verified), "
        "mean time to remediate (MTTR), SLA compliance rate, severity distribution, "
        "aging analysis (0-7d, 7-30d, 30-90d, 90+d), and 12-week trend data."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "description": "List of vulnerability tracking items",
                "items": {"type": "object"},
            },
        },
        "required": ["items"],
    },
)
async def get_metrics(items: list[dict]) -> dict:
    """Calculate vulnerability metrics from vuln items."""
    logger.info("get_metrics called", item_count=len(items))

    metrics = lifecycle.compute_metrics(items)

    return ToolResult(
        success=True,
        data=metrics,
        artifacts=[{
            "type": "raw_output",
            "tool": "vuln_management_metrics",
            "target": "metrics",
            "content": json.dumps(metrics, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "total_items": metrics["status_counts"]["total"],
            "mttr_hours": metrics["mttr_hours"],
            "sla_compliance_rate": metrics["sla_compliance_rate"],
        },
    ).model_dump()


# ======================================================================
# Tool 6: get_sla_breaches
# ======================================================================

@server.tool(
    name="get_sla_breaches",
    description=(
        "Identify vulnerabilities that have breached or are about to breach their SLA. "
        "Checks open and in_progress items against their SLA deadlines. "
        "Items within 48 hours of their deadline are flagged as at-risk. "
        "Returns a list sorted by urgency (most overdue first)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "description": "List of vulnerability tracking items to check",
                "items": {"type": "object"},
            },
        },
        "required": ["items"],
    },
)
async def get_sla_breaches(items: list[dict]) -> dict:
    """Identify SLA-breached or at-risk vulnerabilities."""
    logger.info("get_sla_breaches called", item_count=len(items))

    breaches = lifecycle.get_sla_breaches(items)

    breached_count = sum(1 for b in breaches if b["is_breached"])
    at_risk_count = sum(1 for b in breaches if not b["is_breached"])

    return ToolResult(
        success=True,
        data={
            "breaches": breaches,
            "summary": {
                "total_checked": len(items),
                "total_flagged": len(breaches),
                "breached": breached_count,
                "at_risk": at_risk_count,
            },
        },
        artifacts=[{
            "type": "raw_output",
            "tool": "vuln_management_sla",
            "target": "sla_breaches",
            "content": json.dumps({
                "breached": breached_count,
                "at_risk": at_risk_count,
                "items": [b["vuln_id"] for b in breaches],
            }, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "total_checked": len(items),
            "breached": breached_count,
            "at_risk": at_risk_count,
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
