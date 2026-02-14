import json
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.threat import Threat
from app.models.finding import Finding
from app.models.risk import Risk
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
from app.services.risk_service import RiskService
import structlog

logger = structlog.get_logger()


class RiskAnalysisService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.risk_service = RiskService(db)
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)

    async def run_risk_analysis(
        self, asset_id: str | None = None, run_id: str | None = None
    ) -> dict:
        """Run full ISO 27005 risk analysis across assets, threats, and findings."""
        logger.info("Starting risk analysis", asset_id=asset_id, run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="risk_analysis_start", run_id=run_id,
        )

        # Get assets
        query = select(Asset)
        if asset_id:
            query = query.where(Asset.id == asset_id)
        result = await self.db.execute(query)
        assets = list(result.scalars().all())

        created = 0
        updated = 0
        all_risks = []

        for asset in assets:
            try:
                # Get threats for this asset
                threat_result = await self.db.execute(
                    select(Threat).where(Threat.asset_id == asset.id)
                )
                threats = list(threat_result.scalars().all())

                # Get findings for this asset
                finding_result = await self.db.execute(
                    select(Finding).where(Finding.asset_id == asset.id)
                )
                findings = list(finding_result.scalars().all())

                # Generate risk items from threat+finding combinations
                risk_items = self._generate_risk_scenarios(asset, threats, findings)

                for risk_data in risk_items:
                    risk, is_new = await self._create_or_update_risk(risk_data)
                    if is_new:
                        created += 1
                    else:
                        updated += 1
                    all_risks.append(risk_data)

            except Exception as e:
                logger.error("Risk analysis failed for asset", ip=asset.ip_address, error=str(e))

        # Store artifact
        summary = {
            "risks_created": created,
            "risks_updated": updated,
            "total_assets": len(assets),
        }
        await self.artifact_store.store(
            content=json.dumps(
                {"risks": all_risks, "summary": summary}, indent=2, default=str,
            ),
            artifact_type="raw_output",
            tool_name="risk_analysis",
            target="all_assets" if not asset_id else asset_id,
            run_id=run_id,
            command=f"risk_analysis asset_id={asset_id}",
            parameters={"asset_id": asset_id},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="risk_analysis_complete", run_id=run_id,
            new_value=summary,
        )

        logger.info("Risk analysis complete", created=created, updated=updated)
        return {
            "status": "completed",
            "risks_created": created,
            "risks_updated": updated,
            "total_assets": len(assets),
        }

    def _generate_risk_scenarios(
        self, asset: Asset, threats: list[Threat], findings: list[Finding]
    ) -> list[dict]:
        """Generate risk scenarios from asset+threat+finding combinations."""
        from mcp_servers.risk_engine.analyzer import RiskAnalyzer
        from mcp_servers.risk_engine.treatment import TreatmentAdvisor

        analyzer = RiskAnalyzer()
        advisor = TreatmentAdvisor()

        asset_data = {
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type or "unknown",
            "zone": asset.zone or "lan",
            "criticality": asset.criticality or "medium",
            "exposure": asset.exposure or {},
            "data_types": asset.data_types or [],
            "hostname": asset.hostname,
        }

        risk_items = []

        # Threat-finding pairs
        matched_findings = set()
        for threat in threats:
            # Find related findings
            related_findings = [
                f for f in findings
                if self._is_related(threat, f)
            ]

            if related_findings:
                for finding in related_findings:
                    matched_findings.add(finding.id)
                    finding_data = {
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.category,
                        "exploitability_score": finding.exploitability_score,
                        "cwe_id": finding.cwe_id,
                    }
                    threat_data = {
                        "title": threat.title,
                        "threat_type": threat.threat_type,
                        "confidence": threat.confidence,
                    }

                    analysis = analyzer.analyze(asset_data, threat_data, finding_data)
                    treatment = advisor.suggest(
                        analysis["risk_level"], asset_data, finding_data, threat_data
                    )

                    risk_items.append({
                        "asset_id": asset.id,
                        "threat_id": threat.id,
                        "finding_id": finding.id,
                        **analysis,
                        "recommended_treatment": treatment.get("recommended_treatment"),
                        "treatment_rationale": treatment.get("rationale"),
                    })
            else:
                # Threat without finding (theoretical risk)
                threat_data = {
                    "title": threat.title,
                    "threat_type": threat.threat_type,
                    "confidence": threat.confidence,
                }
                analysis = analyzer.analyze(asset_data, threat_data, None)
                treatment = advisor.suggest(
                    analysis["risk_level"], asset_data, None, threat_data
                )

                # Prefix scenario to distinguish from scan-confirmed risks
                scenario = analysis.get("scenario", "")
                if scenario and not scenario.startswith("[Theoretical]"):
                    analysis["scenario"] = f"[Theoretical] {scenario}"

                risk_items.append({
                    "asset_id": asset.id,
                    "threat_id": threat.id,
                    "finding_id": None,
                    **analysis,
                    "recommended_treatment": treatment.get("recommended_treatment"),
                    "treatment_rationale": treatment.get("rationale"),
                })

        # Findings without matching threats
        for finding in findings:
            if finding.id not in matched_findings and finding.severity != "info":
                finding_data = {
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "exploitability_score": finding.exploitability_score,
                    "cwe_id": finding.cwe_id,
                }
                analysis = analyzer.analyze(asset_data, None, finding_data)
                treatment = advisor.suggest(
                    analysis["risk_level"], asset_data, finding_data, None
                )

                risk_items.append({
                    "asset_id": asset.id,
                    "threat_id": None,
                    "finding_id": finding.id,
                    **analysis,
                    "recommended_treatment": treatment.get("recommended_treatment"),
                    "treatment_rationale": treatment.get("rationale"),
                })

        return risk_items

    def _is_related(self, threat: Threat, finding: Finding) -> bool:
        """Check if a threat and finding are related using strict matching."""
        threat_lower = threat.title.lower()
        finding_lower = finding.title.lower()

        # 1. Exact port number match (e.g., "port 23" in both)
        threat_ports = set(re.findall(r'\bport\s+(\d+)', threat_lower))
        finding_ports = set(re.findall(r'\bport\s+(\d+)', finding_lower))
        if threat_ports and finding_ports and threat_ports & finding_ports:
            return True

        # 2. Specific service name match (not generic words)
        services = [
            "ssh", "telnet", "ftp", "http", "https", "smb", "rdp",
            "vnc", "dns", "smtp", "snmp", "mysql", "postgresql",
            "redis", "mongodb", "upnp", "tls", "ssl", "ldap",
        ]
        for svc in services:
            if svc in threat_lower and svc in finding_lower:
                return True

        # 3. CVE/CWE cross-reference
        if finding.cwe_id and finding.cwe_id in threat_lower:
            return True

        return False

    async def _create_or_update_risk(self, risk_data: dict) -> tuple[Risk, bool]:
        """Create or update a risk item."""
        # Check for existing risk with same asset+threat+finding combination
        query = select(Risk).where(Risk.asset_id == risk_data["asset_id"])
        if risk_data.get("threat_id"):
            query = query.where(Risk.threat_id == risk_data["threat_id"])
        if risk_data.get("finding_id"):
            query = query.where(Risk.finding_id == risk_data["finding_id"])

        result = await self.db.execute(query)
        existing = result.first()

        if existing:
            risk = existing[0]
            # Update with latest analysis
            risk.scenario = risk_data["scenario"]
            risk.likelihood = risk_data["likelihood"]
            risk.likelihood_rationale = risk_data.get("likelihood_rationale")
            risk.impact = risk_data["impact"]
            risk.impact_rationale = risk_data.get("impact_rationale")
            risk.risk_level = risk_data["risk_level"]
            risk.confidentiality_impact = risk_data.get("confidentiality_impact", "none")
            risk.integrity_impact = risk_data.get("integrity_impact", "none")
            risk.availability_impact = risk_data.get("availability_impact", "none")
            risk.likelihood_factors = risk_data.get("likelihood_factors")
            risk.impact_factors = risk_data.get("impact_factors")
            risk.status = "analyzed"
            return risk, False

        risk = Risk(
            asset_id=risk_data["asset_id"],
            threat_id=risk_data.get("threat_id"),
            finding_id=risk_data.get("finding_id"),
            scenario=risk_data["scenario"],
            likelihood=risk_data["likelihood"],
            likelihood_rationale=risk_data.get("likelihood_rationale"),
            impact=risk_data["impact"],
            impact_rationale=risk_data.get("impact_rationale"),
            risk_level=risk_data["risk_level"],
            confidentiality_impact=risk_data.get("confidentiality_impact", "none"),
            integrity_impact=risk_data.get("integrity_impact", "none"),
            availability_impact=risk_data.get("availability_impact", "none"),
            likelihood_factors=risk_data.get("likelihood_factors"),
            impact_factors=risk_data.get("impact_factors"),
            status="analyzed",
        )
        self.db.add(risk)
        await self.db.flush()
        return risk, True
