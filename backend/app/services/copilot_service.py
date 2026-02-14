import json
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.threat import Threat
from app.models.mitre_mapping import MitreMapping
from app.evidence.audit_trail import AuditTrail
from app.config import settings
import structlog

logger = structlog.get_logger()

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class CopilotService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_trail = AuditTrail(db)

    # ─── Investigation (Step 1) ───────────────────────────────────

    async def investigate(self, finding_id: str) -> dict:
        """Full investigation: finding + asset + MITRE + risks + analysis + remediation plan."""
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        # Asset
        asset = None
        if finding.asset_id:
            a_res = await self.db.execute(select(Asset).where(Asset.id == finding.asset_id))
            asset = a_res.scalar_one_or_none()

        # MITRE
        m_res = await self.db.execute(
            select(MitreMapping).where(MitreMapping.finding_id == finding_id)
        )
        mitre = list(m_res.scalars().all())

        # Risks
        r_res = await self.db.execute(
            select(Risk).where(Risk.finding_id == finding_id)
        )
        risks = list(r_res.scalars().all())

        # Build analysis
        analysis = self._build_finding_analysis(finding, asset, mitre, risks)

        # Build remediation plan
        plan = self._build_remediation_plan(finding, asset, {})

        await self.audit_trail.log(
            event_type="ai_suggestion", entity_type="finding",
            entity_id=finding_id, actor="ai_copilot",
            action="investigate",
            new_value={"mitre_count": len(mitre), "risk_count": len(risks)},
        )

        return {
            "finding_id": finding_id,
            "finding": {
                "id": finding.id, "title": finding.title, "severity": finding.severity,
                "status": finding.status, "category": finding.category,
                "description": finding.description, "remediation": finding.remediation,
                "cwe_id": finding.cwe_id, "raw_output_snippet": finding.raw_output_snippet,
            },
            "asset": {
                "id": asset.id, "hostname": asset.hostname, "ip_address": asset.ip_address,
                "asset_type": asset.asset_type, "zone": asset.zone, "criticality": asset.criticality,
                "vendor": asset.vendor, "os_guess": asset.os_guess,
            } if asset else None,
            "mitre_mappings": [
                {"technique_id": m.technique_id, "technique_name": m.technique_name,
                 "tactic": m.tactic, "confidence": m.confidence}
                for m in mitre
            ],
            "risks": [
                {"id": r.id, "scenario": r.scenario, "risk_level": r.risk_level,
                 "likelihood": r.likelihood, "impact": r.impact}
                for r in risks
            ],
            "analysis": analysis,
            "plan": plan,
        }

    def _build_finding_analysis(self, finding: Finding, asset, mitre: list, risks: list) -> dict:
        """Structured analysis: what, why, attack context, risk context, asset context."""
        what = f"{finding.severity.upper()} {finding.category} finding: {finding.title}"
        if finding.description:
            what += f". {finding.description[:300]}"

        why = []
        if finding.severity in ("critical", "high"):
            why.append(f"Severity is {finding.severity} — requires prompt remediation")
        if finding.exploitability_score and finding.exploitability_score >= 7:
            why.append(f"High exploitability score ({finding.exploitability_score}/10)")
        if finding.cve_ids:
            why.append(f"Associated with {len(finding.cve_ids)} known CVE(s)")
        if not why:
            why.append("Standard finding requiring assessment")

        attack_context = []
        for m in mitre:
            attack_context.append(f"{m.technique_id} ({m.technique_name}) — {m.tactic}")
        if not attack_context:
            attack_context.append("No MITRE ATT&CK techniques mapped yet")

        risk_context = []
        for r in risks:
            risk_context.append(f"[{r.risk_level.upper()}] {r.scenario[:200]}")
        if not risk_context:
            risk_context.append("No risk scenarios linked to this finding")

        asset_context = "Unknown asset"
        if asset:
            asset_context = (
                f"{asset.hostname or asset.ip_address} ({asset.asset_type}, "
                f"{asset.zone} zone, criticality: {asset.criticality})"
            )
            if asset.vendor:
                asset_context += f" — {asset.vendor}"
            if asset.os_guess:
                asset_context += f" running {asset.os_guess}"

        return {
            "what": what,
            "why_relevant": why,
            "attack_context": attack_context,
            "risk_context": risk_context,
            "asset_context": asset_context,
        }

    # ─── Execute Remediation (Step 4) ─────────────────────────────

    async def execute_remediation(self, finding_id: str, action: str = "set_in_progress", params: dict | None = None) -> dict:
        """Execute remediation action: typically set status to in_progress."""
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        old_status = finding.status

        if action == "set_in_progress":
            finding.status = "in_progress"
        elif action == "set_fixed":
            finding.status = "fixed"
        elif action == "set_accepted":
            finding.status = "accepted"
        else:
            finding.status = "in_progress"

        finding.updated_at = datetime.utcnow()
        await self.db.flush()

        await self.audit_trail.log(
            event_type="remediation", entity_type="finding",
            entity_id=finding_id, actor="ai_copilot",
            action=f"execute_remediation_{action}",
            old_value={"status": old_status},
            new_value={"status": finding.status, "params": params or {}},
        )

        return {
            "status": "success",
            "finding_id": finding_id,
            "action": action,
            "old_status": old_status,
            "new_status": finding.status,
        }

    # ─── Verify Fix (Step 5) ──────────────────────────────────────

    async def verify_fix(self, finding_id: str, action_id: str = "port_verify", target: str | None = None) -> dict:
        """Run a pentest action to verify if a finding is still reproducible."""
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        # Resolve target from asset if not provided
        if not target and finding.asset_id:
            a_res = await self.db.execute(select(Asset).where(Asset.id == finding.asset_id))
            asset = a_res.scalar_one_or_none()
            if asset:
                target = asset.ip_address

        if not target:
            return {"status": "error", "error": "No target IP available for verification scan"}

        # Run pentest action
        from app.services.pentest_service import PentestService
        pentest = PentestService(self.db)
        scan_result = pentest.validate_scope(target)
        if not scan_result:
            return {"status": "error", "error": f"Target {target} is outside allowed scope"}

        try:
            result_data = await pentest.execute_action(
                action_id=action_id, target=target
            )
        except Exception as e:
            return {"status": "error", "error": f"Verification scan failed: {str(e)}"}

        # Check if the finding was reproduced
        still_vulnerable = False
        scan_findings = result_data.get("findings", [])
        finding_title_lower = finding.title.lower()
        for sf in scan_findings:
            if sf.get("severity", "info") != "info":
                # Check for similar finding
                if sf.get("title", "").lower() in finding_title_lower or finding_title_lower in sf.get("title", "").lower():
                    still_vulnerable = True
                    break

        # If no exact match found but there are non-info findings, still flag
        if not still_vulnerable and any(f.get("severity", "info") != "info" for f in scan_findings):
            still_vulnerable = True

        verdict = "STILL_VULNERABLE" if still_vulnerable else "LIKELY_FIXED"

        await self.audit_trail.log(
            event_type="verification", entity_type="finding",
            entity_id=finding_id, actor="ai_copilot",
            action="verify_fix",
            new_value={
                "verdict": verdict, "action_id": action_id, "target": target,
                "scan_findings": len(scan_findings),
            },
        )

        return {
            "status": "success",
            "finding_id": finding_id,
            "verdict": verdict,
            "scan_result": result_data,
            "scan_findings_count": len(scan_findings),
            "target": target,
        }

    # ─── Existing methods ─────────────────────────────────────────

    async def triage_findings(self, finding_ids: list[str] | None = None) -> dict:
        """Triage findings by priority with actionable suggestions."""
        if finding_ids:
            result = await self.db.execute(
                select(Finding).where(Finding.id.in_(finding_ids))
            )
        else:
            result = await self.db.execute(
                select(Finding).where(Finding.status == "open")
            )
        findings = list(result.scalars().all())

        if not findings:
            return {"findings": [], "total": 0}

        triaged = []
        for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True):
            priority = self._calculate_priority(finding)
            item = {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "priority_score": priority["score"],
                "priority_label": priority["label"],
                "rationale": priority["rationale"],
                "recommended_action": self._recommend_action(finding),
                "effort_estimate": self._estimate_effort(finding),
            }
            triaged.append(item)

        triaged.sort(key=lambda s: s["priority_score"], reverse=True)

        await self.audit_trail.log(
            event_type="ai_suggestion", entity_type="copilot",
            entity_id="triage", actor="ai_copilot",
            action="triage_findings",
            new_value={"finding_count": len(findings), "suggestion_count": len(triaged)},
        )

        return {
            "findings": triaged,
            "total": len(triaged),
            "summary": self._triage_summary(triaged),
        }

    def _calculate_priority(self, finding: Finding) -> dict:
        score = 0.0
        reasons = []

        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}
        sev_score = severity_scores.get(finding.severity, 0)
        score += sev_score
        if sev_score >= 30:
            reasons.append(f"{finding.severity} severity")

        if finding.exploitability_score:
            exploit_score = (finding.exploitability_score / 10) * 30
            score += exploit_score
            if finding.exploitability_score >= 7:
                reasons.append(f"high exploitability ({finding.exploitability_score})")

        category_scores = {"exposure": 15, "vuln": 12, "misconfig": 10, "info": 0}
        cat_score = category_scores.get(finding.category, 5)
        score += cat_score
        if cat_score >= 12:
            reasons.append(f"{finding.category} category")

        if finding.cve_ids and len(finding.cve_ids) > 0:
            score += 15
            reasons.append(f"has {len(finding.cve_ids)} CVE(s)")

        score = min(score, 100)

        if score >= 80:
            label = "critical"
        elif score >= 60:
            label = "high"
        elif score >= 40:
            label = "medium"
        elif score >= 20:
            label = "low"
        else:
            label = "informational"

        return {
            "score": round(score, 1),
            "label": label,
            "rationale": "; ".join(reasons) if reasons else "standard priority",
        }

    def _recommend_action(self, finding: Finding) -> str:
        if finding.severity == "critical":
            return "Immediate remediation required. Isolate affected system if possible."
        if finding.category == "exposure":
            return "Review and restrict network exposure. Check firewall rules."
        if finding.category == "misconfig":
            return "Apply configuration hardening per vendor best practices."
        if finding.severity == "high":
            return "Schedule remediation within SLA window (7 days)."
        if finding.remediation:
            return f"Apply recommended fix: {finding.remediation[:200]}"
        return "Review finding and assess remediation options."

    def _estimate_effort(self, finding: Finding) -> str:
        if finding.category == "misconfig":
            return "low"
        if finding.severity in ("critical", "high") and finding.cve_ids:
            return "medium"
        if finding.category == "exposure":
            return "low"
        return "medium"

    def _triage_summary(self, suggestions: list[dict]) -> dict:
        priority_counts = {}
        for s in suggestions:
            label = s["priority_label"]
            priority_counts[label] = priority_counts.get(label, 0) + 1
        return {
            "total": len(suggestions),
            "by_priority": priority_counts,
            "top_action": suggestions[0]["recommended_action"] if suggestions else None,
        }

    async def suggest_remediation(self, finding_id: str, context: dict | None = None) -> dict:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        asset = None
        if finding.asset_id:
            asset_result = await self.db.execute(
                select(Asset).where(Asset.id == finding.asset_id)
            )
            asset = asset_result.scalar_one_or_none()

        plan = self._build_remediation_plan(finding, asset, context or {})

        await self.audit_trail.log(
            event_type="ai_suggestion", entity_type="finding",
            entity_id=finding_id, actor="ai_copilot",
            action="suggest_remediation",
            new_value={"plan_steps": len(plan.get("steps", []))},
        )

        return {
            "finding_id": finding_id,
            "plan": plan,
            "source": "rule_based",
        }

    def _build_remediation_plan(self, finding: Finding, asset=None, context: dict | None = None) -> dict:
        steps = []
        risk_notes = []

        if finding.category == "exposure":
            steps.extend([
                {"step": 1, "action": "Identify the exposed service and port", "detail": f"Finding: {finding.title}"},
                {"step": 2, "action": "Check if the service needs external access", "detail": "Review business requirement for this exposure"},
                {"step": 3, "action": "Restrict access via firewall rules", "detail": "Apply least-privilege network ACLs"},
                {"step": 4, "action": "Verify the change", "detail": "Re-scan to confirm exposure is mitigated"},
            ])
            risk_notes.append("Restricting access may affect legitimate services")

        elif finding.category == "misconfig":
            steps.extend([
                {"step": 1, "action": "Review current configuration", "detail": f"Service: {finding.source_tool}"},
                {"step": 2, "action": "Apply hardening configuration", "detail": finding.remediation or "Follow vendor hardening guide"},
                {"step": 3, "action": "Test service after changes", "detail": "Verify functionality is not impacted"},
                {"step": 4, "action": "Document the change", "detail": "Update baseline configuration"},
            ])
            risk_notes.append("Configuration changes may require service restart")

        elif finding.category == "vuln":
            steps.extend([
                {"step": 1, "action": "Identify affected software version", "detail": f"Check current version on {asset.hostname or asset.ip_address if asset else 'target'}"},
                {"step": 2, "action": "Check for available patches/updates", "detail": "Consult vendor advisory"},
                {"step": 3, "action": "Apply update in test environment first", "detail": "Validate compatibility before production"},
                {"step": 4, "action": "Apply patch to affected system", "detail": "Schedule maintenance window if needed"},
                {"step": 5, "action": "Verify remediation", "detail": "Re-scan to confirm vulnerability is resolved"},
            ])
            if finding.cve_ids:
                risk_notes.append(f"CVEs: {', '.join(finding.cve_ids[:5])}")

        else:
            steps.extend([
                {"step": 1, "action": "Review the finding details", "detail": finding.description[:200] if finding.description else ""},
                {"step": 2, "action": "Assess risk and impact", "detail": "Determine if action is required"},
                {"step": 3, "action": "Implement fix if needed", "detail": finding.remediation or "Consult documentation"},
            ])

        asset_info = None
        if asset:
            asset_info = {
                "ip": asset.ip_address,
                "hostname": asset.hostname,
                "type": asset.asset_type,
                "criticality": asset.criticality,
                "zone": asset.zone,
            }

        return {
            "finding_title": finding.title,
            "severity": finding.severity,
            "steps": steps,
            "risk_notes": risk_notes,
            "estimated_effort": self._estimate_effort(finding),
            "asset": asset_info,
            "verification": "Run a targeted re-scan after remediation to verify the fix",
        }

    async def suggest_mitre_mappings(self, finding_id: str) -> dict:
        result = await self.db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        from mcp_servers.mitre_mapping.mapper import MitreMapper
        mapper = MitreMapper()
        mappings = mapper.map_finding({
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "source_check": finding.source_check,
            "source_tool": finding.source_tool,
            "cwe_id": finding.cwe_id,
            "description": finding.description,
        })

        suggestions = []
        for m in mappings:
            suggestions.append({
                "technique_id": m["technique_id"],
                "technique_name": m["technique_name"],
                "tactic": m["tactic"],
                "confidence": m["confidence"],
                "rationale": m.get("rationale", ""),
                "source": "rule_based",
            })

        return {
            "finding_id": finding_id,
            "suggestions": suggestions,
            "total": len(suggestions),
        }

    async def generate_narrative(self, run_id: str | None = None, scope: str = "summary") -> dict:
        findings_q = select(Finding)
        risks_q = select(Risk)
        if run_id:
            findings_q = findings_q.where(Finding.run_id == run_id)

        findings_result = await self.db.execute(findings_q)
        findings = list(findings_result.scalars().all())

        risks_result = await self.db.execute(risks_q)
        risks = list(risks_result.scalars().all())

        assets_result = await self.db.execute(select(Asset))
        assets = list(assets_result.scalars().all())

        narrative = self._build_narrative(findings, risks, assets, scope)

        await self.audit_trail.log(
            event_type="ai_suggestion", entity_type="copilot",
            entity_id="narrative", actor="ai_copilot",
            action="generate_narrative",
            new_value={"scope": scope, "run_id": run_id},
        )

        return {
            "narrative": narrative,
            "scope": scope,
            "source": "rule_based",
            "data_points": {
                "findings": len(findings),
                "risks": len(risks),
                "assets": len(assets),
            },
        }

    def _build_narrative(self, findings: list, risks: list, assets: list, scope: str) -> dict:
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        risk_counts = {}
        for r in risks:
            risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

        critical_count = sev_counts.get("critical", 0)
        high_count = sev_counts.get("high", 0)
        total_findings = len(findings)
        total_assets = len(assets)

        exec_summary = (
            f"Assessment of {total_assets} network assets identified {total_findings} findings. "
        )
        if critical_count > 0:
            exec_summary += f"{critical_count} critical finding(s) require immediate attention. "
        if high_count > 0:
            exec_summary += f"{high_count} high-severity finding(s) should be addressed within 7 days. "
        if total_findings == 0:
            exec_summary = f"Assessment of {total_assets} network assets identified no findings. Network posture appears acceptable."

        top_risks = []
        for r in sorted(risks, key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.risk_level, 0), reverse=True)[:5]:
            top_risks.append({
                "scenario": r.scenario[:200] if r.scenario else "",
                "risk_level": r.risk_level,
                "treatment": r.treatment,
            })

        cat_counts = {}
        for f in findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

        sections = {
            "executive_summary": exec_summary,
            "severity_distribution": sev_counts,
            "risk_distribution": risk_counts,
            "category_breakdown": cat_counts,
            "top_risks": top_risks,
            "asset_count": total_assets,
            "finding_count": total_findings,
        }

        if scope == "detailed":
            zone_findings = {}
            for f in findings:
                zone = "unknown"
                zone_findings.setdefault(zone, []).append(f.severity)
            sections["zone_breakdown"] = {
                zone: {"count": len(sevs), "critical": sevs.count("critical"), "high": sevs.count("high")}
                for zone, sevs in zone_findings.items()
            }

        return sections

    async def get_all_suggestions(self) -> dict:
        events = await self.audit_trail.get_trail(
            entity_type="copilot", limit=50
        )
        suggestions = []
        for event in events:
            if event.event_type == "ai_suggestion":
                suggestions.append({
                    "id": event.id,
                    "action": event.action,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "details": event.new_value,
                })
        return {"suggestions": suggestions, "total": len(suggestions)}
