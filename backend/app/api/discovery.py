from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.services.discovery_service import DiscoveryService, FingerprintService
from app.services.threat_service import ThreatService
from app.services.vuln_scan_service import VulnScanService
from app.services.exploit_service import ExploitEnrichmentService
from app.services.mitre_service import MitreService
from app.services.risk_analysis_service import RiskAnalysisService
from app.services.drift_service import DriftService
from app.router_agent.run_manager import RunManager

router = APIRouter()


class DiscoveryRequest(BaseModel):
    subnet: str = "192.168.178.0/24"
    timeout: int = 60
    run_id: str | None = None


class FingerprintRequest(BaseModel):
    asset_id: str | None = None
    run_id: str | None = None
    timeout: int = 120


@router.post("/discover")
async def run_discovery(request: DiscoveryRequest, db: AsyncSession = Depends(get_db)):
    service = DiscoveryService(db)
    result = await service.run_discovery(
        subnet=request.subnet,
        run_id=request.run_id,
        timeout=request.timeout,
    )
    return result


@router.post("/fingerprint")
async def run_fingerprinting(request: FingerprintRequest, db: AsyncSession = Depends(get_db)):
    service = FingerprintService(db)
    result = await service.run_fingerprinting(
        asset_id=request.asset_id,
        run_id=request.run_id,
        timeout=request.timeout,
    )
    return result


class FullScanRequest(BaseModel):
    subnet: str = "192.168.178.0/24"
    timeout: int = 900
    include_threat_modeling: bool = True
    include_vuln_scan: bool = True
    include_exploit_analysis: bool = True
    include_mitre_mapping: bool = True
    include_risk_analysis: bool = True
    create_baseline: bool = True


@router.post("/full-scan")
async def run_full_scan(request: FullScanRequest, db: AsyncSession = Depends(get_db)):
    """Run full pipeline: discovery → fingerprint → threat model → vuln scan → exploit analysis → MITRE → risk."""
    run_manager = RunManager(db)
    run = await run_manager.create_run(scope={"subnets": [request.subnet]})
    step_timeout = request.timeout // 7

    result = {"run_id": run.id}

    # Step 1: Discovery
    await run_manager.start_run(run.id)
    discovery_svc = DiscoveryService(db)
    result["discovery"] = await discovery_svc.run_discovery(
        subnet=request.subnet, run_id=run.id, timeout=step_timeout
    )

    # Step 2: Fingerprinting
    await run_manager.advance_step(run.id, "fingerprinting")
    fingerprint_svc = FingerprintService(db)
    result["fingerprinting"] = await fingerprint_svc.run_fingerprinting(
        run_id=run.id, timeout=step_timeout
    )

    # Step 3: Threat Modeling
    if request.include_threat_modeling:
        await run_manager.advance_step(run.id, "threat_modeling")
        threat_svc = ThreatService(db)
        result["threat_modeling"] = await threat_svc.run_threat_modeling(run_id=run.id)

    # Step 4: Vulnerability Scanning
    if request.include_vuln_scan:
        await run_manager.advance_step(run.id, "vuln_scanning")
        vuln_svc = VulnScanService(db)
        result["vuln_scanning"] = await vuln_svc.run_vuln_scan(
            run_id=run.id, timeout=step_timeout
        )

    # Step 5: Exploit/Exposure Analysis
    if request.include_exploit_analysis:
        await run_manager.advance_step(run.id, "exploit_analysis")
        exploit_svc = ExploitEnrichmentService(db)
        result["exploit_analysis"] = await exploit_svc.run_enrichment(run_id=run.id)

    # Step 6: MITRE ATT&CK Mapping
    if request.include_mitre_mapping:
        await run_manager.advance_step(run.id, "mitre_mapping")
        mitre_svc = MitreService(db)
        result["mitre_mapping"] = await mitre_svc.run_mapping(run_id=run.id)

    # Step 7: Risk Analysis
    if request.include_risk_analysis:
        await run_manager.advance_step(run.id, "risk_analysis")
        risk_svc = RiskAnalysisService(db)
        result["risk_analysis"] = await risk_svc.run_risk_analysis(run_id=run.id)

    # Step 8: Create Baseline (Drift Detection)
    if request.create_baseline:
        await run_manager.advance_step(run.id, "baseline")
        drift_svc = DriftService(db)
        # Extract zone from first discovered asset or default to "lan"
        zone = "lan"
        result["baseline"] = await drift_svc.create_baseline(
            zone=zone, baseline_type="full", run_id=run.id
        )

    await run_manager.advance_step(run.id, "completed")
    result["status"] = "completed"

    return result
