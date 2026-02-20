"""
AI Security Specialist Agent

A rule-based security expert agent that can:
- Answer security questions using assessment data
- Perform triage, investigation, remediation actions
- Provide security recommendations and best practices
- Query assets, findings, risks, threats from the database
"""

import re
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.threat import Threat
from app.models.mitre_mapping import MitreMapping
from app.services.copilot_service import CopilotService
from app.services.report_service import ReportService

import structlog

logger = structlog.get_logger()


class SecurityAgent:
    """IT Security Specialist agent backed by assessment data."""

    ROLE_DESCRIPTION = (
        "I'm your AI Security Specialist — a senior IT security analyst with expertise in "
        "network security, vulnerability management, threat modeling (C4/STRIDE), risk assessment "
        "(ISO 27005), and incident response. I have full access to your assessment data and can "
        "perform actions like triage, investigation, remediation, and verification with your authorization."
    )

    def __init__(self, db: AsyncSession):
        self.db = db
        self.copilot = CopilotService(db)
        self.report_service = ReportService(db)

    async def chat(self, message: str, conversation: list[dict] | None = None) -> dict:
        """Process a user message and return a response."""
        msg_lower = message.lower().strip()

        # Determine intent and route
        try:
            # Greetings
            if self._is_greeting(msg_lower):
                return self._respond(
                    f"Hello! {self.ROLE_DESCRIPTION}\n\n"
                    "Here's what I can help you with:\n"
                    "- **Security posture overview** — \"How's my security?\"\n"
                    "- **Finding analysis** — \"Show me critical findings\" or \"Tell me about [finding]\"\n"
                    "- **Risk analysis** — \"What are my top risks?\"\n"
                    "- **Threat landscape** — \"What threats affect my network?\"\n"
                    "- **Asset inventory** — \"List my assets\" or \"What devices are on my network?\"\n"
                    "- **Triage findings** — \"Triage my findings\" or \"What should I fix first?\"\n"
                    "- **Investigate a finding** — \"Investigate finding [id]\"\n"
                    "- **Remediation advice** — \"How do I fix [issue]?\"\n"
                    "- **Security best practices** — \"How do I secure my router?\"\n"
                    "- **MITRE ATT&CK** — \"What MITRE techniques apply?\"\n\n"
                    "What would you like to know?"
                )

            # Security posture / overview
            if self._matches(msg_lower, ['posture', 'overview', 'how.*security', 'how.*doing',
                                         'status', 'summary', 'dashboard', 'health']):
                return await self._security_posture()

            # Extract finding ID early for action-oriented queries
            finding_id = self._extract_finding_id(msg_lower)

            # Execute actions (highest priority — explicit user commands)
            if self._matches(msg_lower, ['execute', 'run remediation', 'apply fix',
                                         'mark.*fixed', 'mark.*progress']):
                if finding_id:
                    return await self._execute_action(finding_id, msg_lower)
                return self._respond(
                    "I can execute remediation actions on specific findings. "
                    "Please specify which finding you'd like me to act on. "
                    "For example: \"Mark finding abc123 as in progress\""
                )

            # Investigate specific finding (before generic queries)
            if finding_id and self._matches(msg_lower, ['investigate', 'analyze', 'look at',
                                                        'tell me about', 'details', 'explain']):
                return await self._investigate_finding(finding_id)

            # Remediation for specific finding
            if finding_id and self._matches(msg_lower, ['remediat', 'fix', 'patch', 'mitigat']):
                return await self._remediation_advice(finding_id)

            # Triage (check before findings to catch "triage my findings")
            if self._matches(msg_lower, ['triage', 'prioriti', 'what.*fix first', 'what.*should.*fix',
                                         'most important', 'urgent']):
                return await self._run_triage()

            # Findings queries
            if self._matches(msg_lower, ['finding', 'vulnerability', 'vulnerabilities', 'vuln',
                                         'critical finding', 'high finding']):
                return await self._findings_query(msg_lower)

            # Risk queries
            if self._matches(msg_lower, ['risk', 'risks', 'top risk', 'risk level', 'risk assessment']):
                return await self._risks_query(msg_lower)

            # Threat queries
            if self._matches(msg_lower, ['threat', 'threats', 'stride', 'c4', 'threat model']):
                return await self._threats_query(msg_lower)

            # Asset queries
            if self._matches(msg_lower, ['asset', 'assets', 'device', 'devices', 'network',
                                         'inventory', 'what.*on my network']):
                return await self._assets_query(msg_lower)

            # MITRE ATT&CK
            if self._matches(msg_lower, ['mitre', 'att&ck', 'attack', 'technique', 'tactic']):
                return await self._mitre_query(msg_lower)

            # General remediation / best practices
            if self._matches(msg_lower, ['remediat', 'fix', 'patch', 'mitigat', 'harden',
                                         'how.*secure', 'how.*protect', 'best practice',
                                         'recommend', 'should i', 'what about', 'is it safe']):
                return await self._general_remediation(msg_lower)

            # Fallback — try to be helpful
            return await self._smart_fallback(msg_lower)

        except Exception as e:
            logger.error("Security agent error", error=str(e), message=message, exc_info=True)
            return self._respond(
                f"I encountered an error processing your request: {str(e)}\n\n"
                "Could you try rephrasing? Here are some things I can help with:\n"
                "- \"Show me my security posture\"\n"
                "- \"What are the critical findings?\"\n"
                "- \"Triage my findings\""
            )

    # ------------------------------------------------------------------
    # Intent handlers
    # ------------------------------------------------------------------

    async def _security_posture(self) -> dict:
        """Provide a comprehensive security posture overview."""
        summary = await self.report_service.get_summary()

        total_assets = summary.get('total_assets', 0)
        total_findings = summary.get('total_findings', 0)
        total_risks = summary.get('total_risks', 0)
        total_threats = summary.get('total_threats', 0)
        sev = summary.get('severity_breakdown', {})
        risk_bd = summary.get('risk_breakdown', {})

        # Determine posture
        if sev.get('critical', 0) > 0 or risk_bd.get('critical', 0) > 0:
            posture = "CRITICAL"
            posture_msg = "Your security posture is **CRITICAL**. Immediate action is required."
        elif sev.get('high', 0) > 0 or risk_bd.get('high', 0) > 0:
            posture = "HIGH RISK"
            posture_msg = "Your security posture shows **HIGH RISK**. Prioritize remediation of high-severity findings."
        elif sev.get('medium', 0) > 0:
            posture = "MODERATE"
            posture_msg = "Your security posture is **MODERATE**. Address medium-severity findings to improve."
        else:
            posture = "GOOD"
            posture_msg = "Your security posture is **GOOD**. Continue monitoring."

        # Get open findings count
        open_result = await self.db.execute(
            select(func.count(Finding.id)).where(Finding.status == "open")
        )
        open_count = open_result.scalar() or 0

        lines = [
            f"## Security Posture: {posture}\n",
            posture_msg,
            "",
            f"### By the Numbers",
            f"- **{total_assets}** assets discovered",
            f"- **{total_findings}** findings ({open_count} still open)",
            f"- **{total_risks}** risk scenarios identified",
            f"- **{total_threats}** threats modeled",
            "",
            "### Finding Severity Breakdown",
        ]

        for level in ['critical', 'high', 'medium', 'low', 'info']:
            count = sev.get(level, 0)
            if count > 0:
                emoji = {'critical': '!!', 'high': '!', 'medium': '-', 'low': '.', 'info': ' '}
                lines.append(f"  {emoji.get(level, '-')} **{level.upper()}**: {count}")

        if risk_bd:
            lines.append("")
            lines.append("### Risk Level Breakdown")
            for level in ['critical', 'high', 'medium', 'low']:
                count = risk_bd.get(level, 0)
                if count > 0:
                    lines.append(f"  - **{level.upper()}**: {count}")

        lines.append("")
        lines.append("### Recommendations")
        if sev.get('critical', 0) > 0:
            lines.append("1. **Address critical findings immediately** — these represent active exploitable vulnerabilities")
        if sev.get('high', 0) > 0:
            lines.append("2. **Remediate high-severity findings** — schedule within 7 days")
        if total_threats > 0:
            lines.append(f"3. **Review {total_threats} threat scenarios** — ensure mitigations are in place")
        lines.append(f"4. **Triage open findings** — {open_count} findings still need attention")
        lines.append("\nWould you like me to triage the findings or investigate a specific issue?")

        return self._respond("\n".join(lines))

    async def _findings_query(self, msg: str) -> dict:
        """Query and display findings."""
        # Determine filter
        severity_filter = None
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in msg:
                severity_filter = sev
                break

        status_filter = None
        if 'open' in msg:
            status_filter = 'open'
        elif 'fixed' in msg:
            status_filter = 'fixed'
        elif 'in_progress' in msg or 'in progress' in msg:
            status_filter = 'in_progress'

        query = select(Finding).order_by(Finding.severity.desc())
        if severity_filter:
            query = query.where(Finding.severity == severity_filter)
        if status_filter:
            query = query.where(Finding.status == status_filter)
        query = query.limit(15)

        result = await self.db.execute(query)
        findings = result.scalars().all()

        if not findings:
            filter_desc = []
            if severity_filter:
                filter_desc.append(f"severity={severity_filter}")
            if status_filter:
                filter_desc.append(f"status={status_filter}")
            return self._respond(f"No findings found{' with ' + ', '.join(filter_desc) if filter_desc else ''}.")

        lines = [f"## Findings ({len(findings)} shown)\n"]
        filter_parts = []
        if severity_filter:
            filter_parts.append(f"Severity: {severity_filter.upper()}")
        if status_filter:
            filter_parts.append(f"Status: {status_filter}")
        if filter_parts:
            lines.append(f"*Filter: {', '.join(filter_parts)}*\n")

        for f in findings:
            status_icon = {'open': '[OPEN]', 'fixed': '[FIXED]', 'in_progress': '[IN PROGRESS]',
                           'accepted': '[ACCEPTED]', 'verified': '[VERIFIED]'}.get(f.status, f'[{f.status}]')
            lines.append(
                f"- **{f.severity.upper()}** {status_icon} {f.title}\n"
                f"  `{f.id[:8]}` | {f.category} | {f.source_tool}"
            )
            if f.cve_ids:
                cves = f.cve_ids if isinstance(f.cve_ids, list) else []
                if cves:
                    lines.append(f"  CVEs: {', '.join(cves[:5])}")

        lines.append(f"\nTo investigate a specific finding, say: \"Investigate finding [id]\"")
        return self._respond("\n".join(lines))

    async def _risks_query(self, msg: str) -> dict:
        """Query and display risks."""
        query = select(Risk).order_by(Risk.risk_level.desc()).limit(15)

        level_filter = None
        for level in ['critical', 'high', 'medium', 'low']:
            if level in msg:
                level_filter = level
                query = select(Risk).where(Risk.risk_level == level).order_by(Risk.risk_level.desc()).limit(15)
                break

        result = await self.db.execute(query)
        risks = result.scalars().all()

        if not risks:
            return self._respond("No risk scenarios found in the assessment data.")

        lines = [f"## Risk Scenarios ({len(risks)} shown)\n"]
        if level_filter:
            lines.append(f"*Filter: Risk Level = {level_filter.upper()}*\n")

        for r in risks:
            cia = []
            if r.confidentiality_impact and r.confidentiality_impact != 'none':
                cia.append(f"C:{r.confidentiality_impact}")
            if r.integrity_impact and r.integrity_impact != 'none':
                cia.append(f"I:{r.integrity_impact}")
            if r.availability_impact and r.availability_impact != 'none':
                cia.append(f"A:{r.availability_impact}")

            lines.append(
                f"- **{r.risk_level.upper()}** — {r.scenario}\n"
                f"  Likelihood: {r.likelihood} | Impact: {r.impact}"
                + (f" | CIA: {', '.join(cia)}" if cia else "")
                + (f"\n  Treatment: {r.treatment}" if r.treatment else "")
            )

        lines.append(f"\n{len(risks)} risk scenarios shown. Ask about specific risk levels for more detail.")
        return self._respond("\n".join(lines))

    async def _threats_query(self, msg: str) -> dict:
        """Query and display threats."""
        query = select(Threat).order_by(Threat.created_at.desc()).limit(20)

        # Filter by C4 level
        c4_filter = None
        if 'system context' in msg or 'c4 level 1' in msg or 'trust boundar' in msg:
            c4_filter = 'system_context'
        elif 'container' in msg or 'c4 level 2' in msg or 'zone' in msg:
            c4_filter = 'container'
        elif 'component' in msg or 'c4 level 3' in msg or 'per-asset' in msg:
            c4_filter = 'component'

        if c4_filter:
            query = select(Threat).where(Threat.c4_level == c4_filter).order_by(Threat.created_at.desc()).limit(20)

        # Filter by STRIDE category
        stride_filter = None
        for cat in ['spoofing', 'tampering', 'repudiation', 'information_disclosure',
                     'denial_of_service', 'elevation_of_privilege']:
            if cat.replace('_', ' ') in msg or cat.replace('_', '') in msg:
                stride_filter = cat
                query = select(Threat).where(Threat.threat_type == cat).order_by(Threat.created_at.desc()).limit(20)
                break

        result = await self.db.execute(query)
        threats = result.scalars().all()

        if not threats:
            return self._respond("No threats found matching your criteria.")

        # Count by C4 level
        c4_counts = {}
        stride_counts = {}
        for t in threats:
            c4_counts[t.c4_level or 'unknown'] = c4_counts.get(t.c4_level or 'unknown', 0) + 1
            stride_counts[t.threat_type or 'unknown'] = stride_counts.get(t.threat_type or 'unknown', 0) + 1

        lines = [f"## Threat Landscape ({len(threats)} shown)\n"]

        if c4_filter:
            lines.append(f"*Filter: C4 Level = {c4_filter}*\n")
        if stride_filter:
            lines.append(f"*Filter: STRIDE = {stride_filter}*\n")

        if not c4_filter and not stride_filter:
            lines.append("### C4 Decomposition")
            for level in ['system_context', 'container', 'component']:
                if c4_counts.get(level, 0) > 0:
                    label = {'system_context': 'System Context (L1)', 'container': 'Container (L2)',
                             'component': 'Component (L3)'}.get(level, level)
                    lines.append(f"  - **{label}**: {c4_counts[level]} threats")

            lines.append("\n### STRIDE Categories")
            for cat in ['spoofing', 'tampering', 'repudiation', 'information_disclosure',
                        'denial_of_service', 'elevation_of_privilege']:
                if stride_counts.get(cat, 0) > 0:
                    lines.append(f"  - **{cat.replace('_', ' ').title()}**: {stride_counts[cat]}")
            lines.append("")

        for t in threats[:10]:
            c4_label = {'system_context': '[L1]', 'container': '[L2]', 'component': '[L3]'}.get(
                t.c4_level or '', '')
            lines.append(
                f"- {c4_label} **{t.threat_type or 'unknown'}** — {t.title}\n"
                f"  Confidence: {t.confidence:.0%}"
                + (f" | Zone: {t.zone}" if t.zone else "")
                + (f" | Boundary: {t.trust_boundary}" if t.trust_boundary else "")
            )
            if t.stride_category_detail:
                lines.append(f"  _{t.stride_category_detail[:120]}_")

        if len(threats) > 10:
            lines.append(f"\n_Showing 10 of {len(threats)}. Filter by C4 level or STRIDE category for more._")

        return self._respond("\n".join(lines))

    async def _assets_query(self, msg: str) -> dict:
        """Query and display assets."""
        query = select(Asset).order_by(Asset.criticality.desc(), Asset.ip_address).limit(30)

        zone_filter = None
        for zone in ['lan', 'wan', 'iot', 'dmz', 'guest']:
            if zone in msg:
                zone_filter = zone
                query = select(Asset).where(Asset.zone == zone).order_by(Asset.ip_address).limit(30)
                break

        result = await self.db.execute(query)
        assets = result.scalars().all()

        if not assets:
            return self._respond("No assets found in the inventory.")

        # Group by zone
        zones: dict[str, list] = {}
        for a in assets:
            z = a.zone or 'unknown'
            if z not in zones:
                zones[z] = []
            zones[z].append(a)

        lines = [f"## Asset Inventory ({len(assets)} shown)\n"]
        if zone_filter:
            lines.append(f"*Filter: Zone = {zone_filter.upper()}*\n")

        for zone, zone_assets in sorted(zones.items()):
            lines.append(f"### {zone.upper()} Zone ({len(zone_assets)} assets)")
            for a in zone_assets:
                name = a.hostname or a.ip_address
                lines.append(
                    f"- **{name}** ({a.ip_address}) — {a.asset_type}"
                    + (f" | {a.vendor}" if a.vendor else "")
                    + (f" | OS: {a.os_guess}" if a.os_guess else "")
                    + f" | Criticality: {a.criticality}"
                )
            lines.append("")

        return self._respond("\n".join(lines))

    async def _run_triage(self) -> dict:
        """Run triage and present results."""
        result = await self.copilot.triage_findings()
        findings = result.get('findings', [])

        if not findings:
            return self._respond(
                "No open findings to triage. Your environment looks clean!\n\n"
                "If you've run a scan recently, all findings may already be addressed."
            )

        lines = [f"## Finding Triage — {len(findings)} Open Findings\n"]
        lines.append("Prioritized by severity, exploitability, and impact:\n")

        for i, f in enumerate(findings[:20], 1):
            score = f.get('priority_score', 0)
            urgency = 'URGENT' if score >= 70 else 'MODERATE' if score >= 40 else 'LOW'
            lines.append(
                f"{i}. [{urgency}] **{f['severity'].upper()}** — {f['title']}\n"
                f"   Priority Score: {score}/100 | {f['category']} | Effort: {f.get('effort_estimate', 'unknown')}\n"
                f"   Action: {f.get('recommended_action', 'Review')}\n"
                f"   ID: `{f['finding_id'][:8]}`"
            )

        triage_summary = result.get('summary', {})
        if triage_summary:
            lines.append(f"\n### Summary")
            lines.append(f"- Urgent (score >= 70): {triage_summary.get('urgent_count', 0)}")
            lines.append(f"- Moderate (40-69): {triage_summary.get('moderate_count', 0)}")
            lines.append(f"- Low priority (<40): {triage_summary.get('low_count', 0)}")

        lines.append("\nTo investigate any finding, say: \"Investigate finding [id]\"")
        return self._respond("\n".join(lines))

    async def _investigate_finding(self, finding_id: str) -> dict:
        """Investigate a specific finding."""
        finding_id = await self._resolve_finding_id(finding_id)
        result = await self.copilot.investigate(finding_id)
        if result.get('status') == 'error':
            return self._respond(f"Could not investigate finding: {result.get('error', 'Not found')}")

        f = result.get('finding', {})
        asset = result.get('asset')
        analysis = result.get('analysis', {})
        plan = result.get('plan', {})
        mitre = result.get('mitre_mappings', [])
        risks = result.get('risks', [])

        lines = [f"## Investigation: {f.get('title', 'Unknown')}\n"]
        lines.append(f"**Severity**: {f.get('severity', 'unknown').upper()} | "
                      f"**Status**: {f.get('status', 'unknown')} | "
                      f"**Category**: {f.get('category', 'unknown')}")

        if asset:
            lines.append(f"\n### Affected Asset")
            lines.append(f"- **{asset.get('hostname') or asset.get('ip_address')}** ({asset.get('ip_address')})")
            lines.append(f"  Zone: {asset.get('zone')} | Type: {asset.get('asset_type')} | Criticality: {asset.get('criticality')}")

        lines.append(f"\n### Analysis")
        lines.append(f"**What**: {analysis.get('what', 'N/A')}")
        if analysis.get('why_relevant'):
            lines.append(f"**Why it matters**: {'; '.join(analysis['why_relevant'])}")
        if analysis.get('attack_context'):
            lines.append(f"**Attack context**: {'; '.join(analysis['attack_context'])}")
        lines.append(f"**Asset context**: {analysis.get('asset_context', 'N/A')}")

        if mitre:
            lines.append(f"\n### MITRE ATT&CK Mappings")
            for m in mitre:
                lines.append(f"- **{m['technique_id']}** ({m['tactic']}) — {m['technique_name']}")

        if risks:
            lines.append(f"\n### Associated Risks")
            for r in risks:
                lines.append(f"- **{r['risk_level'].upper()}** — {r['scenario']}")

        if plan:
            lines.append(f"\n### Remediation Plan")
            lines.append(f"*Estimated effort: {plan.get('estimated_effort', 'unknown')}*\n")
            for step in plan.get('steps', []):
                lines.append(f"{step['step']}. **{step['action']}**\n   {step['detail']}")
            if plan.get('risk_notes'):
                lines.append(f"\n**Risk notes**: {'; '.join(plan['risk_notes'])}")

        lines.append(f"\n---\nTo proceed with remediation, say: \"Execute remediation for finding {finding_id[:8]}\"")
        return self._respond("\n".join(lines), actions=['investigate', 'remediate'])

    async def _remediation_advice(self, finding_id: str) -> dict:
        """Provide remediation advice for a specific finding."""
        finding_id = await self._resolve_finding_id(finding_id)
        result = await self.copilot.suggest_remediation(finding_id)
        if result.get('status') == 'error':
            return self._respond(f"Could not get remediation advice: {result.get('error', 'Not found')}")

        lines = [f"## Remediation Advice\n"]
        lines.append(f"**Finding**: {result.get('title', 'Unknown')}")
        lines.append(f"**Severity**: {result.get('severity', 'unknown').upper()}\n")

        plan = result.get('plan', {})
        if plan:
            lines.append("### Steps")
            for step in plan.get('steps', []):
                lines.append(f"{step['step']}. **{step['action']}** — {step['detail']}")

        if result.get('remediation'):
            lines.append(f"\n### Additional Guidance\n{result['remediation']}")

        return self._respond("\n".join(lines))

    async def _general_remediation(self, msg: str) -> dict:
        """Provide general security advice based on the message content."""
        advice_topics = {
            'router': (
                "## Securing Your Router\n\n"
                "1. **Change default credentials** — Use a strong, unique password for admin access\n"
                "2. **Update firmware** — Check manufacturer's site for latest firmware\n"
                "3. **Disable WPS** — Wi-Fi Protected Setup has known vulnerabilities\n"
                "4. **Use WPA3/WPA2-AES** — Never use WEP or WPA-TKIP\n"
                "5. **Disable remote management** — Unless absolutely needed\n"
                "6. **Enable firewall** — Use SPI firewall with default-deny for inbound\n"
                "7. **Disable UPnP** — Prevents automatic port forwarding\n"
                "8. **Set DNS** — Use encrypted DNS (DoH/DoT) with trusted resolvers\n"
                "9. **Create guest network** — Isolate IoT and guest devices\n"
                "10. **Enable logging** — Monitor for suspicious activity"
            ),
            'iot': (
                "## Securing IoT Devices\n\n"
                "1. **Isolate on separate VLAN/network** — Use a dedicated IoT zone\n"
                "2. **Change default passwords** — Every device needs unique credentials\n"
                "3. **Update firmware regularly** — Enable auto-updates where possible\n"
                "4. **Disable unnecessary services** — Turn off UPnP, telnet, SSH if not needed\n"
                "5. **Monitor network traffic** — Watch for unusual outbound connections\n"
                "6. **Use local control** — Prefer local APIs over cloud when possible\n"
                "7. **Check for known CVEs** — Search vendor + model in NVD database"
            ),
            'password': (
                "## Password Security Best Practices\n\n"
                "1. **Use a password manager** — Generate and store unique passwords\n"
                "2. **Minimum 16 characters** — Length matters more than complexity\n"
                "3. **Enable MFA everywhere** — Especially for admin accounts\n"
                "4. **Never reuse passwords** — One breach shouldn't compromise everything\n"
                "5. **Check for breaches** — Use haveibeenpwned.com to check exposure\n"
                "6. **Use passkeys where supported** — More secure than passwords"
            ),
            'ssh': (
                "## Securing SSH Access\n\n"
                "1. **Use key-based authentication** — Disable password auth\n"
                "2. **Change default port** — Move from 22 to a non-standard port\n"
                "3. **Disable root login** — Use sudo instead\n"
                "4. **Use fail2ban** — Block brute force attempts\n"
                "5. **Limit allowed users** — Use AllowUsers directive\n"
                "6. **Use Ed25519 keys** — Stronger than RSA\n"
                "7. **Set idle timeout** — ClientAliveInterval 300, ClientAliveCountMax 2"
            ),
            'firewall': (
                "## Firewall Best Practices\n\n"
                "1. **Default deny inbound** — Only allow explicitly needed ports\n"
                "2. **Restrict outbound** — Block unnecessary outbound traffic\n"
                "3. **Log denied connections** — Monitor for scanning/probing\n"
                "4. **Use zone-based policies** — Different rules per network zone\n"
                "5. **Review rules regularly** — Remove stale/unused rules\n"
                "6. **Enable SPI** — Stateful packet inspection for connection tracking"
            ),
            'tls': (
                "## TLS/SSL Security\n\n"
                "1. **Use TLS 1.2+** — Disable SSLv3, TLS 1.0, TLS 1.1\n"
                "2. **Strong cipher suites** — Prefer AEAD ciphers (AES-GCM, ChaCha20)\n"
                "3. **Valid certificates** — Use Let's Encrypt for free, auto-renewed certs\n"
                "4. **Enable HSTS** — HTTP Strict Transport Security\n"
                "5. **Certificate pinning** — For critical internal services\n"
                "6. **Regular rotation** — Rotate certificates before expiry"
            ),
            'dns': (
                "## DNS Security\n\n"
                "1. **Use encrypted DNS** — DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)\n"
                "2. **Use trusted resolvers** — Cloudflare (1.1.1.1), Quad9 (9.9.9.9)\n"
                "3. **Enable DNSSEC validation** — Protects against DNS spoofing\n"
                "4. **Block known malicious domains** — Use DNS-level filtering\n"
                "5. **Monitor DNS queries** — Watch for DGA domains and tunneling"
            ),
        }

        for topic, advice in advice_topics.items():
            if topic in msg:
                return self._respond(advice)

        # Generic security advice
        summary = await self.report_service.get_summary()
        sev = summary.get('severity_breakdown', {})

        lines = ["## Security Recommendations\n"]
        lines.append("Based on your assessment data, here are my top recommendations:\n")

        if sev.get('critical', 0) > 0:
            lines.append(f"1. **Fix {sev['critical']} critical findings** — These are your highest priority")
        if sev.get('high', 0) > 0:
            lines.append(f"2. **Address {sev['high']} high-severity findings** — Schedule within 7 days")
        lines.append("3. **Segment your network** — Isolate IoT devices from main LAN")
        lines.append("4. **Update all firmware** — Routers, switches, access points, IoT devices")
        lines.append("5. **Enable encryption** — Use WPA3/WPA2-AES for Wi-Fi, TLS for services")
        lines.append("6. **Review access controls** — Disable default accounts, enforce strong passwords")
        lines.append("7. **Monitor continuously** — Re-run assessments regularly")
        lines.append("\nAsk me about any specific topic: router, IoT, SSH, TLS, DNS, firewall, passwords")

        return self._respond("\n".join(lines))

    async def _mitre_query(self, msg: str) -> dict:
        """Query MITRE ATT&CK mappings."""
        result = await self.db.execute(
            select(MitreMapping).order_by(MitreMapping.confidence.desc()).limit(20)
        )
        mappings = result.scalars().all()

        if not mappings:
            return self._respond("No MITRE ATT&CK mappings found. Run a full assessment to generate mappings.")

        # Group by tactic
        tactics: dict[str, list] = {}
        for m in mappings:
            tactic = m.tactic or 'unknown'
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(m)

        lines = [f"## MITRE ATT&CK Mappings ({len(mappings)} techniques)\n"]
        for tactic, techs in sorted(tactics.items()):
            lines.append(f"### {tactic.replace('_', ' ').title()}")
            for t in techs:
                conf = f"{t.confidence:.0%}" if t.confidence else "N/A"
                lines.append(f"- **{t.technique_id}** — {t.technique_name} (Confidence: {conf})")
            lines.append("")

        return self._respond("\n".join(lines))

    async def _execute_action(self, finding_id: str, msg: str) -> dict:
        """Execute an action on a finding."""
        finding_id = await self._resolve_finding_id(finding_id)
        action = 'set_in_progress'
        if 'fixed' in msg or 'resolved' in msg:
            action = 'set_fixed'
        elif 'accept' in msg:
            action = 'set_accepted'

        action_label = {'set_in_progress': 'In Progress', 'set_fixed': 'Fixed', 'set_accepted': 'Accepted'}

        result = await self.copilot.execute_remediation(finding_id, action)
        if result.get('status') == 'error':
            return self._respond(f"Failed to execute action: {result.get('error', 'Unknown error')}")

        return self._respond(
            f"Done! Finding status updated:\n\n"
            f"- **Action**: {action_label.get(action, action)}\n"
            f"- **Old Status**: {result.get('old_status', 'unknown')}\n"
            f"- **New Status**: {result.get('new_status', 'unknown')}\n\n"
            f"The action has been logged in the audit trail.",
            actions=['executed']
        )

    async def _smart_fallback(self, msg: str) -> dict:
        """Try to provide a useful response when intent is unclear."""
        # Check if it's a question about a specific IP
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', msg)
        if ip_match:
            ip = ip_match.group(1)
            result = await self.db.execute(select(Asset).where(Asset.ip_address == ip))
            asset = result.scalar_one_or_none()
            if asset:
                # Get findings for this asset
                findings_result = await self.db.execute(
                    select(Finding).where(Finding.asset_id == asset.id).order_by(Finding.severity.desc()).limit(10)
                )
                findings = findings_result.scalars().all()

                lines = [f"## Asset: {asset.hostname or asset.ip_address}\n"]
                lines.append(f"- **IP**: {asset.ip_address}")
                lines.append(f"- **Type**: {asset.asset_type}")
                lines.append(f"- **Zone**: {asset.zone}")
                lines.append(f"- **Criticality**: {asset.criticality}")
                if asset.vendor:
                    lines.append(f"- **Vendor**: {asset.vendor}")
                if asset.os_guess:
                    lines.append(f"- **OS**: {asset.os_guess}")

                if findings:
                    lines.append(f"\n### Findings ({len(findings)})")
                    for f in findings:
                        lines.append(f"- **{f.severity.upper()}** — {f.title} [{f.status}]")
                else:
                    lines.append("\nNo findings associated with this asset.")

                return self._respond("\n".join(lines))

        # Check if it matches a finding title
        if len(msg) > 10:
            result = await self.db.execute(
                select(Finding).where(Finding.title.ilike(f"%{msg[:50]}%")).limit(5)
            )
            findings = result.scalars().all()
            if findings:
                lines = [f"## Found {len(findings)} matching finding(s)\n"]
                for f in findings:
                    lines.append(f"- **{f.severity.upper()}** — {f.title}\n  ID: `{f.id[:8]}` | {f.category} | {f.status}")
                lines.append(f"\nSay \"Investigate finding [id]\" for full details.")
                return self._respond("\n".join(lines))

        return self._respond(
            "I'm not sure what you're asking about. As your security specialist, I can help with:\n\n"
            "- **\"How's my security?\"** — Security posture overview\n"
            "- **\"Show critical findings\"** — Filter findings by severity\n"
            "- **\"What are my top risks?\"** — Risk analysis\n"
            "- **\"Triage my findings\"** — Prioritized action list\n"
            "- **\"Investigate finding [id]\"** — Deep-dive into a specific finding\n"
            "- **\"How do I secure my router?\"** — Best practice advice\n"
            "- **\"192.168.1.1\"** — Asset lookup by IP\n"
            "- **\"What MITRE techniques apply?\"** — ATT&CK mapping\n\n"
            "What would you like to know?"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_greeting(msg: str) -> bool:
        greetings = ['hello', 'hi', 'hey', 'greetings', 'good morning', 'good afternoon',
                     'good evening', 'howdy', 'sup', 'yo', 'hola', 'hallo']
        return any(msg.startswith(g) or msg == g for g in greetings)

    @staticmethod
    def _matches(msg: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if '.*' in pattern or '\\' in pattern:
                if re.search(pattern, msg):
                    return True
            elif pattern in msg:
                return True
        return False

    @staticmethod
    def _extract_finding_id(msg: str) -> str | None:
        """Extract a finding ID (UUID or partial) from the message."""
        # Full UUID
        uuid_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', msg)
        if uuid_match:
            return uuid_match.group(0)
        # Partial UUID (at least 8 hex chars)
        partial_match = re.search(r'\b([0-9a-f]{8,})\b', msg)
        if partial_match:
            return partial_match.group(1)
        return None

    async def _resolve_finding_id(self, partial_id: str) -> str | None:
        """Resolve a partial finding ID to a full UUID."""
        if len(partial_id) == 36 and '-' in partial_id:
            return partial_id
        result = await self.db.execute(
            select(Finding.id).where(Finding.id.like(f"{partial_id}%")).limit(1)
        )
        row = result.scalar_one_or_none()
        return row if row else partial_id

    @staticmethod
    def _respond(content: str, actions: list[str] | None = None) -> dict:
        return {
            "role": "assistant",
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
            "actions": actions or [],
        }
