import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.finding import Finding
from app.models.threat import Threat
from app.models.mitre_mapping import MitreMapping
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
import structlog

logger = structlog.get_logger()


class MitreService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)

    async def run_mapping(
        self, run_id: str | None = None
    ) -> dict:
        """Map all findings and threats to MITRE ATT&CK techniques."""
        logger.info("Starting MITRE mapping", run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="mitre_mapping_start", run_id=run_id,
        )

        from mcp_servers.mitre_mapping.mapper import MitreMapper
        mapper = MitreMapper()

        # Map findings
        result = await self.db.execute(select(Finding))
        findings = list(result.scalars().all())

        created = 0
        skipped = 0
        all_mappings = []

        for finding in findings:
            finding_data = {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "category": finding.category,
                "source_tool": finding.source_tool,
                "source_check": finding.source_check,
                "cwe_id": finding.cwe_id,
                "cve_ids": finding.cve_ids or [],
            }

            mappings = mapper.map_finding(finding_data)
            for m in mappings:
                mapping, is_new = await self._create_deduplicated_mapping(
                    finding_id=finding.id,
                    threat_id=None,
                    mapping_data=m,
                )
                if is_new:
                    created += 1
                    all_mappings.append(m)
                else:
                    skipped += 1

        # Map threats
        result = await self.db.execute(select(Threat))
        threats = list(result.scalars().all())

        for threat in threats:
            threat_data = {
                "title": threat.title,
                "description": threat.description,
                "threat_type": threat.threat_type,
                "zone": threat.zone,
            }

            mappings = mapper.map_threat(threat_data)
            for m in mappings:
                mapping, is_new = await self._create_deduplicated_mapping(
                    finding_id=None,
                    threat_id=threat.id,
                    mapping_data=m,
                )
                if is_new:
                    created += 1
                    all_mappings.append(m)
                else:
                    skipped += 1

        # Store artifact
        summary = {
            "mappings_created": created,
            "mappings_skipped_duplicate": skipped,
            "findings_processed": len(findings),
            "threats_processed": len(threats),
        }
        await self.artifact_store.store(
            content=json.dumps(
                {"mappings": all_mappings, "summary": summary},
                indent=2, default=str,
            ),
            artifact_type="raw_output",
            tool_name="mitre_mapping_service",
            target="all",
            run_id=run_id,
            command="mitre_mapping",
            parameters={},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="mitre_mapping_complete", run_id=run_id,
            new_value=summary,
        )

        logger.info("MITRE mapping complete", created=created, skipped=skipped)
        return {
            "status": "completed",
            "mappings_created": created,
            "mappings_skipped_duplicate": skipped,
            "findings_processed": len(findings),
            "threats_processed": len(threats),
        }

    async def _create_deduplicated_mapping(
        self,
        finding_id: str | None,
        threat_id: str | None,
        mapping_data: dict,
    ) -> tuple[MitreMapping, bool]:
        """Create a MITRE mapping if it doesn't already exist."""
        # Check for duplicate
        query = select(MitreMapping).where(
            MitreMapping.technique_id == mapping_data["technique_id"],
        )
        if finding_id:
            query = query.where(MitreMapping.finding_id == finding_id)
        if threat_id:
            query = query.where(MitreMapping.threat_id == threat_id)

        result = await self.db.execute(query)
        existing = result.scalar_one_or_none()

        if existing:
            # Update confidence if higher
            if mapping_data.get("confidence", 0) > existing.confidence:
                existing.confidence = mapping_data["confidence"]
                existing.rationale = mapping_data.get("rationale", existing.rationale)
            return existing, False

        mapping = MitreMapping(
            finding_id=finding_id,
            threat_id=threat_id,
            technique_id=mapping_data["technique_id"],
            technique_name=mapping_data["technique_name"],
            tactic=mapping_data.get("tactic", ""),
            confidence=mapping_data.get("confidence", 0.5),
            source=mapping_data.get("source", "rule"),
            rationale=mapping_data.get("rationale", ""),
        )
        self.db.add(mapping)
        await self.db.flush()
        return mapping, True

    async def export_navigator_layer(self) -> dict:
        """Export all mappings as an ATT&CK Navigator layer."""
        from mcp_servers.mitre_mapping.navigator import NavigatorExporter

        result = await self.db.execute(select(MitreMapping))
        mappings = result.scalars().all()

        mapping_dicts = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "source": m.source,
                "rationale": m.rationale or "",
            }
            for m in mappings
        ]

        exporter = NavigatorExporter()
        return exporter.export_layer(mapping_dicts)
