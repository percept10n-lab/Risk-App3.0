import json
from datetime import datetime, date, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.finding import Finding
from app.models.asset import Asset
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.models.vulnerability import Vulnerability
from app.evidence.audit_trail import AuditTrail
import structlog

logger = structlog.get_logger()

SLA_DAYS = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
    "info": None,
}

VALID_TRANSITIONS = {
    "open": ["in_progress", "accepted", "exception"],
    "in_progress": ["fixed", "open"],
    "fixed": ["verified", "open"],
    "accepted": ["open"],
    "exception": ["open"],
    "verified": [],
}


class VulnMgmtService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_trail = AuditTrail(db)

    async def create_from_findings(self, run_id: str | None = None) -> dict:
        """Create vulnerability tracking items from all open findings."""
        result = await self.db.execute(
            select(Finding).where(Finding.status == "open")
        )
        findings = list(result.scalars().all())

        created = 0
        skipped = 0

        for finding in findings:
            if finding.severity == "info":
                skipped += 1
                continue

            # Check if vuln item already exists
            existing = await self.db.execute(
                select(Vulnerability).where(Vulnerability.finding_id == finding.id)
            )
            if existing.scalar_one_or_none():
                skipped += 1
                continue

            sla_days = SLA_DAYS.get(finding.severity)
            sla_deadline = None
            if sla_days is not None:
                sla_deadline = (datetime.utcnow() + timedelta(days=sla_days)).date()

            vuln = Vulnerability(
                finding_id=finding.id,
                status="open",
                sla_deadline=sla_deadline,
                comments=[],
                history=[{
                    "status": "open",
                    "changed_by": "system",
                    "timestamp": datetime.utcnow().isoformat(),
                    "note": f"Auto-created from finding: {finding.title}",
                }],
            )
            self.db.add(vuln)
            created += 1

        await self.db.flush()

        logger.info("Vuln items created", created=created, skipped=skipped)
        return {
            "status": "completed",
            "vulns_created": created,
            "vulns_skipped": skipped,
            "total_findings": len(findings),
        }

    async def update_status(
        self, vuln_id: str, new_status: str, comment: str | None = None, actor: str = "user"
    ) -> dict:
        """Update vulnerability status with validation."""
        result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.id == vuln_id)
        )
        vuln = result.scalar_one_or_none()
        if not vuln:
            return {"status": "error", "error": "Vulnerability not found"}

        # Validate transition
        allowed = VALID_TRANSITIONS.get(vuln.status, [])
        if new_status not in allowed:
            return {
                "status": "error",
                "error": f"Invalid transition: {vuln.status} → {new_status}. Allowed: {allowed}",
            }

        old_status = vuln.status
        vuln.status = new_status
        vuln.updated_at = datetime.utcnow()

        # Update history
        history = vuln.history or []
        history.append({
            "status": new_status,
            "changed_by": actor,
            "timestamp": datetime.utcnow().isoformat(),
            "note": comment,
        })
        vuln.history = history

        # Add comment if provided
        if comment:
            comments = vuln.comments or []
            comments.append({
                "author": actor,
                "text": comment,
                "timestamp": datetime.utcnow().isoformat(),
            })
            vuln.comments = comments

        # Audit trail
        await self.audit_trail.log(
            event_type="status_change", entity_type="vulnerability",
            entity_id=vuln_id, actor=actor,
            action="update_status",
            old_value={"status": old_status},
            new_value={"status": new_status},
            rationale=comment,
        )

        await self.db.flush()

        return {
            "status": "updated",
            "vuln_id": vuln_id,
            "old_status": old_status,
            "new_status": new_status,
        }

    async def get_metrics(self) -> dict:
        """Calculate vulnerability management metrics."""
        result = await self.db.execute(select(Vulnerability))
        vulns = list(result.scalars().all())

        if not vulns:
            return {
                "total": 0, "open": 0, "in_progress": 0, "fixed": 0,
                "accepted": 0, "exception": 0, "verified": 0,
                "sla_compliance_rate": 0.0, "mttr_days": 0.0,
            }

        status_counts = {}
        for v in vulns:
            status_counts[v.status] = status_counts.get(v.status, 0) + 1

        # Calculate MTTR for fixed/verified items
        fixed_items = [v for v in vulns if v.status in ("fixed", "verified")]
        mttr_days = 0.0
        if fixed_items:
            total_days = 0.0
            count = 0
            for v in fixed_items:
                if v.history:
                    # Find time from open to fixed
                    open_time = None
                    fix_time = None
                    for h in v.history:
                        if h.get("status") == "open" and not open_time:
                            try:
                                open_time = datetime.fromisoformat(h["timestamp"])
                            except (ValueError, KeyError):
                                pass
                        if h.get("status") == "fixed" and not fix_time:
                            try:
                                fix_time = datetime.fromisoformat(h["timestamp"])
                            except (ValueError, KeyError):
                                pass
                    if open_time and fix_time:
                        total_days += (fix_time - open_time).total_seconds() / 86400
                        count += 1
            if count > 0:
                mttr_days = round(total_days / count, 1)

        # SLA compliance
        sla_checked = [v for v in vulns if v.sla_deadline and v.status in ("fixed", "verified")]
        sla_compliant = 0
        for v in sla_checked:
            # Check if fixed before deadline
            fixed_date = None
            if v.history:
                for h in v.history:
                    if h.get("status") == "fixed":
                        try:
                            fixed_date = datetime.fromisoformat(h["timestamp"]).date()
                        except (ValueError, KeyError):
                            pass
            if fixed_date and fixed_date <= v.sla_deadline:
                sla_compliant += 1
        sla_rate = round(sla_compliant / max(len(sla_checked), 1) * 100, 1)

        # SLA breaches
        now = date.today()
        breached = [
            v for v in vulns
            if v.sla_deadline and v.status in ("open", "in_progress")
            and v.sla_deadline < now
        ]
        at_risk = [
            v for v in vulns
            if v.sla_deadline and v.status in ("open", "in_progress")
            and now <= v.sla_deadline <= now + timedelta(days=3)
        ]

        return {
            "total": len(vulns),
            "open": status_counts.get("open", 0),
            "in_progress": status_counts.get("in_progress", 0),
            "fixed": status_counts.get("fixed", 0),
            "accepted": status_counts.get("accepted", 0),
            "exception": status_counts.get("exception", 0),
            "verified": status_counts.get("verified", 0),
            "mttr_days": mttr_days,
            "sla_compliance_rate": sla_rate,
            "sla_breached": len(breached),
            "sla_at_risk": len(at_risk),
        }

    async def get_enriched_finding(self, finding_id: str) -> dict | None:
        """Get finding with full context for vulnerability management."""
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        # Asset
        asset = None
        if finding.asset_id:
            a_res = await self.db.execute(select(Asset).where(Asset.id == finding.asset_id))
            asset = a_res.scalar_one_or_none()

        # MITRE Mappings
        m_res = await self.db.execute(
            select(MitreMapping).where(MitreMapping.finding_id == finding_id)
        )
        mitre = list(m_res.scalars().all())

        # Risks
        r_res = await self.db.execute(
            select(Risk).where(Risk.finding_id == finding_id)
        )
        risks = list(r_res.scalars().all())

        return {
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "status": finding.status,
                "description": finding.description,
                "remediation": finding.remediation,
                "cwe_id": finding.cwe_id,
                "cve_ids": finding.cve_ids or [],
                "cpe": finding.cpe,
                "raw_output_snippet": finding.raw_output_snippet,
                "source_tool": finding.source_tool,
                "source_check": finding.source_check,
                "exploitability_score": finding.exploitability_score,
                "exploitability_rationale": finding.exploitability_rationale,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
                "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
            },
            "asset": {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "asset_type": asset.asset_type,
                "zone": asset.zone,
                "criticality": asset.criticality,
                "vendor": asset.vendor,
                "os_guess": asset.os_guess,
            } if asset else None,
            "mitre_mappings": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "confidence": m.confidence,
                }
                for m in mitre
            ],
            "risks": [
                {
                    "id": r.id,
                    "scenario": r.scenario,
                    "risk_level": r.risk_level,
                    "likelihood": r.likelihood,
                    "impact": r.impact,
                    "treatment": r.treatment,
                }
                for r in risks
            ],
        }
