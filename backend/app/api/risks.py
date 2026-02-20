from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.risk import Risk
from app.models.asset import Asset
from app.models.threat import Threat
from app.models.finding import Finding
from app.models.mitre_mapping import MitreMapping
from app.models.override import Override
from app.models.audit_event import AuditEvent
from app.schemas.risk import RiskCreate, RiskUpdate, RiskResponse, TreatmentRequest
from app.schemas.common import PaginatedResponse, OverrideRequest
from app.services.risk_analysis_service import RiskAnalysisService
from app.services.exploit_service import ExploitEnrichmentService
from app.services.pagination import paginate

router = APIRouter()


@router.get("")
async def list_risks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    finding_id: str | None = None,
    risk_level: str | None = None,
    status: str | None = None,
    include_asset: bool = False,
    db: AsyncSession = Depends(get_db),
):
    query = select(Risk)
    if asset_id:
        query = query.where(Risk.asset_id == asset_id)
    if finding_id:
        query = query.where(Risk.finding_id == finding_id)
    if risk_level:
        query = query.where(Risk.risk_level == risk_level)
    if status:
        query = query.where(Risk.status == status)
    query = query.order_by(Risk.created_at.desc())

    items, total = await paginate(db, query, page, page_size)

    serialized = [RiskResponse.model_validate(r).model_dump() for r in items]

    if not include_asset:
        return {"items": serialized, "total": total, "page": page, "page_size": page_size}

    # Enrich with asset data
    asset_cache: dict[str, dict | None] = {}
    asset_ids = list({r.asset_id for r in items if r.asset_id})
    if asset_ids:
        asset_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
        for a in asset_result.scalars().all():
            asset_cache[a.id] = {"id": a.id, "hostname": a.hostname, "ip_address": a.ip_address}

    for item_dict in serialized:
        item_dict["asset"] = asset_cache.get(item_dict["asset_id"])

    return {"items": serialized, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def risk_stats(db: AsyncSession = Depends(get_db)):
    """Return aggregate risk counts by level and status."""
    level_result = await db.execute(
        select(Risk.risk_level, sa_func.count(Risk.id)).group_by(Risk.risk_level)
    )
    by_level = dict(level_result.all())

    status_result = await db.execute(
        select(Risk.status, sa_func.count(Risk.id)).group_by(Risk.status)
    )
    by_status = dict(status_result.all())

    total_result = await db.execute(select(sa_func.count(Risk.id)))
    total = total_result.scalar() or 0

    return {"total": total, "by_level": by_level, "by_status": by_status}


@router.post("", response_model=RiskResponse, status_code=201)
async def create_risk(risk_in: RiskCreate, db: AsyncSession = Depends(get_db)):
    risk = Risk(**risk_in.model_dump())
    db.add(risk)
    await db.flush()
    await db.refresh(risk)
    return risk


# --- Static routes BEFORE /{risk_id} to avoid path conflicts ---

@router.get("/matrix")
async def get_risk_matrix(db: AsyncSession = Depends(get_db)):
    """Get the risk matrix configuration, distribution, and cell-level risk data."""
    from app.services.risk_service import RiskService
    service = RiskService(db)
    stats = await service.get_risk_stats()
    treatment_stats = await service.get_treatment_stats()

    # Build cell_risks: {likelihood}_{impact} -> list of risks in that cell
    # Treated risks with residual_risk_level are shown in parentheses at their
    # residual position and removed from the original cell
    all_risks_result = await db.execute(select(Risk))
    all_risks = list(all_risks_result.scalars().all())

    cell_risks: dict[str, list] = {}
    for r in all_risks:
        is_treated = r.status == "treated" and r.residual_risk_level is not None
        key = f"{r.likelihood}_{r.impact}"
        entry = {
            "id": r.id,
            "risk_level": r.residual_risk_level if is_treated else r.risk_level,
            "scenario": r.scenario[:100] if r.scenario else "",
            "status": r.status,
            "treated": is_treated,
            "original_risk_level": r.risk_level if is_treated else None,
        }
        if key not in cell_risks:
            cell_risks[key] = []
        cell_risks[key].append(entry)

    thresholds = {
        "low": {"acceptable": True, "allowed_treatments": ["accept", "mitigate", "transfer", "avoid"], "requires_escalation": False, "max_days": None},
        "medium": {"acceptable": True, "allowed_treatments": ["mitigate", "transfer", "avoid"], "requires_escalation": False, "max_days": 90},
        "high": {"acceptable": False, "allowed_treatments": ["mitigate", "transfer", "avoid"], "requires_escalation": True, "max_days": 30},
        "critical": {"acceptable": False, "allowed_treatments": ["mitigate", "avoid"], "requires_escalation": True, "max_days": 7},
    }

    return {
        "matrix": service.matrix,
        "risk_distribution": stats,
        "treatment_distribution": treatment_stats,
        "cell_risks": cell_risks,
        "thresholds": thresholds,
    }


class RiskAnalysisRequest(BaseModel):
    asset_id: str | None = None
    run_id: str | None = None


class EnrichmentRequest(BaseModel):
    asset_id: str | None = None
    run_id: str | None = None


@router.post("/analyze")
async def run_risk_analysis(request: RiskAnalysisRequest, db: AsyncSession = Depends(get_db)):
    """Run full ISO 27005 risk analysis across assets, threats, and findings."""
    service = RiskAnalysisService(db)
    return await service.run_risk_analysis(
        asset_id=request.asset_id,
        run_id=request.run_id,
    )


@router.post("/enrich")
async def run_exploit_enrichment(request: EnrichmentRequest, db: AsyncSession = Depends(get_db)):
    """Enrich findings with exploitability scores and CVE/CWE data."""
    service = ExploitEnrichmentService(db)
    return await service.run_enrichment(
        asset_id=request.asset_id,
        run_id=request.run_id,
    )


# --- Dynamic routes with {risk_id} ---

@router.get("/{risk_id}/full-context")
async def get_risk_full_context(risk_id: str, db: AsyncSession = Depends(get_db)):
    """Get a risk with full linked context: asset, threat, finding, MITRE mappings."""
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    risk_data = RiskResponse.model_validate(risk).model_dump()

    # Asset
    asset_data = None
    if risk.asset_id:
        ares = await db.execute(select(Asset).where(Asset.id == risk.asset_id))
        asset = ares.scalar_one_or_none()
        if asset:
            asset_data = {
                "id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "asset_type": asset.asset_type,
                "zone": asset.zone,
                "criticality": asset.criticality,
            }

    # Threat
    threat_data = None
    if risk.threat_id:
        tres = await db.execute(select(Threat).where(Threat.id == risk.threat_id))
        threat = tres.scalar_one_or_none()
        if threat:
            threat_data = {
                "id": threat.id,
                "title": threat.title,
                "threat_type": threat.threat_type,
                "confidence": threat.confidence,
                "description": threat.description,
            }

    # Finding
    finding_data = None
    if risk.finding_id:
        fres = await db.execute(select(Finding).where(Finding.id == risk.finding_id))
        finding = fres.scalar_one_or_none()
        if finding:
            finding_data = {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "source_tool": finding.source_tool,
                "exploitability_score": finding.exploitability_score,
                "exploitability_rationale": finding.exploitability_rationale,
                "cwe_id": finding.cwe_id,
                "remediation": finding.remediation,
            }

    # MITRE mappings (via finding_id or threat_id)
    mitre_mappings = []
    mitre_query_conditions = []
    if risk.finding_id:
        mitre_query_conditions.append(MitreMapping.finding_id == risk.finding_id)
    if risk.threat_id:
        mitre_query_conditions.append(MitreMapping.threat_id == risk.threat_id)

    if mitre_query_conditions:
        from sqlalchemy import or_
        mres = await db.execute(
            select(MitreMapping).where(or_(*mitre_query_conditions))
        )
        for m in mres.scalars().all():
            mitre_mappings.append({
                "id": m.id,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
            })

    risk_data["asset"] = asset_data
    risk_data["threat"] = threat_data
    risk_data["finding"] = finding_data
    risk_data["mitre_mappings"] = mitre_mappings

    return risk_data


@router.get("/{risk_id}", response_model=RiskResponse)
async def get_risk(risk_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return risk


@router.put("/{risk_id}", response_model=RiskResponse)
async def update_risk(risk_id: str, risk_in: RiskUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    for field, value in risk_in.model_dump(exclude_unset=True).items():
        setattr(risk, field, value)
    risk.updated_at = datetime.utcnow()
    await db.flush()
    await db.refresh(risk)
    return risk


@router.post("/{risk_id}/treatment", response_model=RiskResponse)
async def treat_risk(risk_id: str, treatment_in: TreatmentRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")

    for field, value in treatment_in.model_dump(exclude_unset=True).items():
        setattr(risk, field, value)
    risk.status = "treated"
    # Update risk_level to residual if provided
    if treatment_in.residual_risk_level:
        risk.risk_level = treatment_in.residual_risk_level
    risk.updated_at = datetime.utcnow()

    audit = AuditEvent(
        event_type="treatment", entity_type="risk", entity_id=risk_id,
        actor="user", action="apply_treatment",
        new_value=treatment_in.model_dump(mode="json"),
    )
    db.add(audit)
    await db.flush()
    await db.refresh(risk)
    return risk


@router.post("/{risk_id}/override", status_code=201)
async def override_risk(risk_id: str, override_in: OverrideRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Risk).where(Risk.id == risk_id))
    risk = result.scalar_one_or_none()
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    original_value = getattr(risk, override_in.field, None)
    override = Override(
        entity_type="risk", entity_id=risk_id, field=override_in.field,
        original_value={"value": original_value}, override_value={"value": override_in.value},
        rationale=override_in.rationale, overridden_by="user",
    )
    db.add(override)
    setattr(risk, override_in.field, override_in.value)
    audit = AuditEvent(
        event_type="override", entity_type="risk", entity_id=risk_id,
        actor="user", action=f"override_{override_in.field}",
        old_value={"value": original_value}, new_value={"value": override_in.value},
        rationale=override_in.rationale,
    )
    db.add(audit)
    return {"status": "overridden", "field": override_in.field}
