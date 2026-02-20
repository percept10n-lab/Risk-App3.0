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

    # ─── Gather (Step 3.1) ──────────────────────────────────────

    async def gather(self, finding_id: str) -> dict:
        """Step 3.1: Gather patches, updates, and check admin requirements."""
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {"status": "error", "error": "Finding not found"}

        asset = None
        if finding.asset_id:
            a_res = await self.db.execute(select(Asset).where(Asset.id == finding.asset_id))
            asset = a_res.scalar_one_or_none()

        # Build remediation plan to inform admin-check
        plan = self._build_remediation_plan(finding, asset, {})

        updates = self._discover_updates(finding, asset)
        admin_required, admin_actions, admin_explanation = self._check_admin_requirements(
            finding, asset, plan.get("steps", [])
        )

        # Build summary
        update_count = len(updates)
        update_types = set(u["type"] for u in updates)
        type_labels = {
            "software_update": "software update(s)",
            "firmware_update": "firmware update(s)",
            "config_change": "configuration change(s)",
        }
        parts = []
        for t in ("software_update", "firmware_update", "config_change"):
            count = sum(1 for u in updates if u["type"] == t)
            if count:
                parts.append(f"{count} {type_labels[t]}")
        summary = ", ".join(parts) if parts else "No updates identified"
        if admin_required:
            summary += ". Admin access required."
        else:
            summary += ". No admin access required."

        await self.audit_trail.log(
            event_type="ai_suggestion", entity_type="finding",
            entity_id=finding_id, actor="ai_copilot",
            action="gather",
            new_value={
                "update_count": update_count,
                "admin_required": admin_required,
            },
        )

        return {
            "finding_id": finding_id,
            "asset": {
                "ip": asset.ip_address if asset else None,
                "hostname": asset.hostname if asset else None,
                "vendor": asset.vendor if asset else None,
                "os_guess": asset.os_guess if asset else None,
                "asset_type": asset.asset_type if asset else None,
            } if asset else None,
            "updates": updates,
            "admin_required": admin_required,
            "admin_actions": admin_actions,
            "admin_explanation": admin_explanation,
            "summary": summary,
        }

    def _discover_updates(self, finding: Finding, asset) -> list[dict]:
        """Rule-based patch/update lookup based on finding + asset context."""
        updates = []
        title_lower = finding.title.lower() if finding.title else ""
        source_check = (finding.source_check or "").lower()
        source_tool = (finding.source_tool or "").lower()
        category = (finding.category or "").lower()
        raw_output = (finding.raw_output_snippet or "").lower()
        vendor = (asset.vendor or "").lower() if asset else ""
        asset_type = (asset.asset_type or "").lower() if asset else ""
        os_guess = (asset.os_guess or "").lower() if asset else ""

        # SSH findings
        if "ssh" in title_lower or "ssh" in source_check or "ssh" in source_tool:
            updates.append({
                "name": "OpenSSH Update",
                "type": "software_update",
                "description": "Upgrade OpenSSH to the latest stable version to resolve weak algorithms, deprecated ciphers, or known vulnerabilities",
                "vendor_url": "https://www.openssh.com/releasenotes.html",
                "integrity": "Verify GPG signature with the OpenBSD signing key. Downloads should be over HTTPS only.",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })
            updates.append({
                "name": "SSH Daemon Configuration Hardening",
                "type": "config_change",
                "description": "Update sshd_config to disable weak key exchange algorithms, ciphers, and MACs. Restrict authentication methods.",
                "vendor_url": "https://man.openbsd.org/sshd_config",
                "integrity": "N/A — configuration change, no download required",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })

        # TLS / SSL findings
        elif "tls" in title_lower or "ssl" in title_lower or "certificate" in title_lower or "tls" in source_check:
            updates.append({
                "name": "OpenSSL / LibreSSL Update",
                "type": "software_update",
                "description": "Upgrade the TLS library to the latest version to resolve protocol weaknesses or deprecated cipher suites",
                "vendor_url": "https://www.openssl.org/source/",
                "integrity": "Verify SHA256 checksum and GPG signature from openssl.org. Downloads must be over HTTPS.",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })
            # Check if it's a web-server config issue
            if "cipher" in title_lower or "protocol" in title_lower or "header" in source_check:
                updates.append({
                    "name": "Web Server TLS Configuration",
                    "type": "config_change",
                    "description": "Update web server configuration to enforce TLS 1.2+ and strong cipher suites",
                    "vendor_url": "https://ssl-config.mozilla.org/",
                    "integrity": "N/A — configuration change, no download required",
                    "priority": "high",
                })

        # HTTP header findings
        elif "header" in title_lower or "http" in source_check or "header" in source_check:
            updates.append({
                "name": "HTTP Security Headers Configuration",
                "type": "config_change",
                "description": "Add or update security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP, etc.) in the web server configuration",
                "vendor_url": "https://owasp.org/www-project-secure-headers/",
                "integrity": "N/A — configuration change, no download required",
                "priority": "medium" if finding.severity in ("medium", "low", "info") else "high",
            })

        # Default credential findings
        elif "default" in title_lower and ("credential" in title_lower or "password" in title_lower):
            updates.append({
                "name": "Credential Change",
                "type": "config_change",
                "description": "Change default credentials to strong, unique passwords. Enable multi-factor authentication if supported.",
                "vendor_url": "",
                "integrity": "N/A — credential change, no download required",
                "priority": "critical",
            })

        # DNS findings
        elif "dns" in title_lower or "dns" in source_check:
            updates.append({
                "name": "DNS Server Update / Configuration",
                "type": "config_change",
                "description": "Update DNS server configuration to disable zone transfers, enable DNSSEC, and restrict recursive queries",
                "vendor_url": "https://www.isc.org/bind/",
                "integrity": "Verify package signature from distribution repository or ISC directly",
                "priority": "medium",
            })

        # Firmware / Router / IoT
        elif asset_type in ("router", "iot", "appliance", "switch", "access_point") or "firmware" in title_lower:
            vendor_url = ""
            if "fritz" in vendor:
                vendor_url = "https://fritz.box"
            elif "meross" in vendor:
                vendor_url = "https://www.meross.com/support"
            elif "ubiquiti" in vendor or "unifi" in vendor:
                vendor_url = "https://ui.com/download"
            elif "mikrotik" in vendor:
                vendor_url = "https://mikrotik.com/download"
            elif vendor:
                vendor_url = f"Check {asset.vendor} support portal for firmware updates"
            else:
                vendor_url = "Check device vendor support portal for firmware updates"

            updates.append({
                "name": "Firmware Update",
                "type": "firmware_update",
                "description": f"Check for and apply the latest firmware update from the device vendor to address known vulnerabilities",
                "vendor_url": vendor_url,
                "integrity": "Verify firmware checksum against vendor-published SHA256 hash. Download only from official vendor portal over HTTPS.",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })

        # CVE-based findings (generic)
        elif finding.cve_ids and len(finding.cve_ids) > 0:
            cve_list = ", ".join(finding.cve_ids[:5])
            updates.append({
                "name": "Vendor Patch for " + (finding.cve_ids[0] if finding.cve_ids else "known CVEs"),
                "type": "software_update",
                "description": f"Apply vendor-issued patches addressing: {cve_list}. Consult the vendor advisory for specific update instructions.",
                "vendor_url": f"https://cvefeed.io/vuln/detail/{finding.cve_ids[0]}" if finding.cve_ids else "",
                "integrity": "Verify package signatures and checksums from the official vendor repository. Downloads must be over HTTPS.",
                "priority": "critical" if finding.severity == "critical" else "high",
            })

        # Generic fallback based on category
        elif category == "vuln":
            updates.append({
                "name": "Software Update",
                "type": "software_update",
                "description": f"Check for available patches addressing: {finding.title}. Consult vendor documentation for update procedures.",
                "vendor_url": "",
                "integrity": "Verify package signatures from official vendor repository",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })
        elif category == "misconfig":
            updates.append({
                "name": "Configuration Hardening",
                "type": "config_change",
                "description": f"Apply configuration changes to address: {finding.title}",
                "vendor_url": "",
                "integrity": "N/A — configuration change, no download required",
                "priority": "medium",
            })
        elif category == "exposure":
            updates.append({
                "name": "Firewall / ACL Configuration",
                "type": "config_change",
                "description": f"Restrict network exposure by updating firewall rules or access control lists",
                "vendor_url": "",
                "integrity": "N/A — configuration change, no download required",
                "priority": "high" if finding.severity in ("critical", "high") else "medium",
            })

        return updates

    def _check_admin_requirements(self, finding: Finding, asset, plan_steps: list) -> tuple[bool, list[dict], str]:
        """Determine if admin access is needed and explain why."""
        admin_actions = []
        title_lower = (finding.title or "").lower()
        source_check = (finding.source_check or "").lower()
        category = (finding.category or "").lower()
        asset_type = (asset.asset_type or "").lower() if asset else ""
        hostname = (asset.hostname or asset.ip_address) if asset else "the target device"

        # Service restart
        if any(kw in title_lower or kw in source_check for kw in ("ssh", "tls", "ssl", "http", "dns", "ftp", "smtp")):
            admin_actions.append({
                "action": "Restart the affected service after applying changes",
                "reason": "The service daemon must be restarted to load the new configuration or updated binary",
                "impact": "Active connections to the service will be briefly interrupted during restart",
            })

        # Firmware flash
        if asset_type in ("router", "iot", "appliance", "switch", "access_point") or "firmware" in title_lower:
            admin_actions.append({
                "action": "Flash firmware update to the device",
                "reason": "Firmware updates require administrative access to the device management interface",
                "impact": "The device will reboot during the firmware update process. Network connectivity through this device will be temporarily lost.",
            })

        # Config file edit
        if category == "misconfig" or any(kw in title_lower for kw in ("config", "header", "cipher", "protocol", "algorithm")):
            admin_actions.append({
                "action": "Modify service configuration files",
                "reason": "Configuration files for system services are typically owned by root and require elevated privileges to edit",
                "impact": "Incorrect configuration changes could prevent the service from starting. A backup will be recommended before changes.",
            })

        # Firewall rule change
        if category == "exposure" or "firewall" in title_lower or "port" in title_lower:
            admin_actions.append({
                "action": "Update firewall rules or network ACLs",
                "reason": "Firewall and network access control changes require administrative privileges",
                "impact": "Overly restrictive rules could block legitimate traffic. Changes should be tested before applying to production.",
            })

        # Password change
        if "credential" in title_lower or "password" in title_lower or "default" in title_lower:
            admin_actions.append({
                "action": "Change device or service credentials",
                "reason": "Changing credentials on the device itself requires administrator access to the management interface",
                "impact": "All sessions using the old credentials will be disconnected. Ensure new credentials are securely documented.",
            })

        # Software update/install
        if category == "vuln" and not admin_actions:
            admin_actions.append({
                "action": "Install software update or security patch",
                "reason": "Package installation and system updates require elevated (root/admin) privileges",
                "impact": "The service may need to be restarted after patching. Schedule a maintenance window if the system is in production.",
            })

        admin_required = len(admin_actions) > 0

        # Build explanation
        if admin_required:
            action_summaries = [a["action"].lower() for a in admin_actions]
            admin_explanation = (
                f"This remediation requires administrator access to {hostname} because the following actions "
                f"need elevated privileges: {'; '.join(action_summaries)}. "
                f"Please review each action below and grant explicit consent before proceeding."
            )
        else:
            admin_explanation = ""

        return admin_required, admin_actions, admin_explanation

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

        await self.db.commit()

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
        for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity or "info", 0), reverse=True):
            try:
                priority = self._calculate_priority(finding)
                item = {
                    "finding_id": finding.id,
                    "title": finding.title or "Untitled Finding",
                    "severity": finding.severity or "info",
                    "category": finding.category or "unknown",
                    "priority_score": priority["score"],
                    "priority_label": priority["label"],
                    "rationale": priority["rationale"],
                    "recommended_action": self._recommend_action(finding),
                    "effort_estimate": self._estimate_effort(finding),
                }
                triaged.append(item)
            except Exception as e:
                logger.warning("Failed to triage finding", finding_id=finding.id, error=str(e))
                continue

        triaged.sort(key=lambda s: s["priority_score"], reverse=True)

        try:
            await self.audit_trail.log(
                event_type="ai_suggestion", entity_type="copilot",
                entity_id="triage", actor="ai_copilot",
                action="triage_findings",
                new_value={"finding_count": len(findings), "suggestion_count": len(triaged)},
            )
            await self.db.commit()
        except Exception as e:
            logger.warning("Audit trail log failed during triage", error=str(e))

        return {
            "findings": triaged,
            "total": len(triaged),
            "summary": self._triage_summary(triaged),
        }

    def _calculate_priority(self, finding: Finding) -> dict:
        score = 0.0
        reasons = []

        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}
        sev_score = severity_scores.get(finding.severity or "info", 0)
        score += sev_score
        if sev_score >= 30:
            reasons.append(f"{finding.severity} severity")

        if finding.exploitability_score:
            exploit_score = (finding.exploitability_score / 10) * 30
            score += exploit_score
            if finding.exploitability_score >= 7:
                reasons.append(f"high exploitability ({finding.exploitability_score})")

        category_scores = {"exposure": 15, "vuln": 12, "misconfig": 10, "info": 0}
        cat_score = category_scores.get(finding.category or "info", 5)
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
