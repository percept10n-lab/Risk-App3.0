"""
Threat Intel API — landing dashboard, CVEs, advisories, sources, ingest.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.models.threatintel import CVEItem, AdvisoryItem, TriageItem, ConnectorStatus, MonitoredIdentity
from app.schemas.threatintel import (
    CVEItemResponse, AdvisoryItemResponse, TriageItemResponse,
    ConnectorStatusResponse, KeyCounters, ThreatIntelDashboard, IngestResult,
    MonitoredIdentityCreate, MonitoredIdentityResponse, BreachHitResponse,
    PasswordCheckRequest, PasswordCheckResponse, IdentitySummary, BreachCheckResult,
)
from app.schemas.common import PaginatedResponse
from app.services.threatintel_service import (
    run_full_ingest, ingest_kev, ingest_epss, ingest_nvd, ingest_bsi,
    rebuild_triage, get_dashboard_data,
)
from app.services.identity_monitor_service import (
    add_identity, remove_identity, list_identities, get_identity_breaches,
    check_all_identities, check_single_identity, check_password_hash,
    get_identity_summary,
)

router = APIRouter()


# ── Dashboard (landing page data) ─────────────────────────────────────────

@router.get("/dashboard", response_model=ThreatIntelDashboard)
async def get_threatintel_dashboard(
    hours: int = Query(72, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
):
    """Landing page dashboard: triage, counters, KEV, EPSS, advisories, sources."""
    data = await get_dashboard_data(db, hours=hours)
    return ThreatIntelDashboard(
        triage=[TriageItemResponse.model_validate(t) for t in data["triage"]],
        counters=KeyCounters(**data["counters"]),
        kev_latest=[CVEItemResponse.model_validate(c) for c in data["kev_latest"]],
        epss_top=[CVEItemResponse.model_validate(c) for c in data["epss_top"]],
        advisories_latest=[AdvisoryItemResponse.model_validate(a) for a in data["advisories_latest"]],
        connectors=[ConnectorStatusResponse.model_validate(c) for c in data["connectors"]],
    )


# ── CVE / Vulnerabilities ────────────────────────────────────────────────

@router.get("/vulnerabilities", response_model=PaginatedResponse[CVEItemResponse])
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    kev_only: bool = Query(False),
    min_epss: float | None = Query(None, ge=0, le=1),
    min_cvss: float | None = Query(None, ge=0, le=10),
    vendor: str | None = None,
    search: str | None = None,
    sort_by: str = Query("urgency", pattern="^(urgency|epss|cvss|kev_date|updated)$"),
    db: AsyncSession = Depends(get_db),
):
    """Filterable CVE list with facets."""
    query = select(CVEItem)
    count_query = select(func.count(CVEItem.id))

    conditions = []
    if kev_only:
        conditions.append(CVEItem.kev_listed == True)
    if min_epss is not None:
        conditions.append(CVEItem.epss_score >= min_epss)
    if min_cvss is not None:
        conditions.append(CVEItem.cvss_base >= min_cvss)
    if vendor:
        conditions.append(CVEItem.vendor_project.ilike(f"%{vendor}%"))
    if search:
        conditions.append(
            CVEItem.cve_id.ilike(f"%{search}%") | CVEItem.description.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    total = await db.scalar(count_query) or 0

    # Sorting
    order_map = {
        "urgency": CVEItem.kev_listed.desc(),
        "epss": CVEItem.epss_score.desc(),
        "cvss": CVEItem.cvss_base.desc(),
        "kev_date": CVEItem.kev_date_added.desc(),
        "updated": CVEItem.updated_at.desc(),
    }
    query = query.order_by(order_map.get(sort_by, CVEItem.updated_at.desc()))
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/vulnerabilities/{cve_id}", response_model=CVEItemResponse)
async def get_vulnerability(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Single CVE detail."""
    result = await db.execute(select(CVEItem).where(CVEItem.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return cve


# ── Advisories ────────────────────────────────────────────────────────────

@router.get("/advisories", response_model=PaginatedResponse[AdvisoryItemResponse])
async def list_advisories(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    issuer: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Filterable advisory list."""
    query = select(AdvisoryItem)
    count_query = select(func.count(AdvisoryItem.id))

    conditions = []
    if issuer:
        conditions.append(AdvisoryItem.issuer == issuer)
    if severity:
        conditions.append(AdvisoryItem.severity == severity)
    if search:
        conditions.append(
            AdvisoryItem.title.ilike(f"%{search}%") | AdvisoryItem.summary.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    total = await db.scalar(count_query) or 0
    query = query.order_by(AdvisoryItem.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/advisories/{advisory_id}", response_model=AdvisoryItemResponse)
async def get_advisory(advisory_id: str, db: AsyncSession = Depends(get_db)):
    """Single advisory detail."""
    result = await db.execute(select(AdvisoryItem).where(AdvisoryItem.advisory_id == advisory_id))
    adv = result.scalar_one_or_none()
    if not adv:
        raise HTTPException(404, f"Advisory {advisory_id} not found")
    return adv


# ── Sources / Connectors ─────────────────────────────────────────────────

@router.get("/sources", response_model=list[ConnectorStatusResponse])
async def list_sources(db: AsyncSession = Depends(get_db)):
    """All connector statuses."""
    result = await db.execute(select(ConnectorStatus).order_by(ConnectorStatus.connector_name))
    return result.scalars().all()


# ── Ingest endpoints ─────────────────────────────────────────────────────

@router.post("/ingest", response_model=list[IngestResult])
async def ingest_all(db: AsyncSession = Depends(get_db)):
    """Run all connectors and rebuild triage. Returns per-connector results."""
    results = await run_full_ingest(db)
    return results


@router.post("/ingest/{connector}", response_model=IngestResult)
async def ingest_single(connector: str, db: AsyncSession = Depends(get_db)):
    """Run a single connector."""
    runners = {
        "cisa_kev": ingest_kev,
        "first_epss": ingest_epss,
        "nvd": ingest_nvd,
        "cert_bund": ingest_bsi,
    }
    if connector not in runners:
        raise HTTPException(400, f"Unknown connector: {connector}. Available: {list(runners.keys())}")
    result = await runners[connector](db)
    await rebuild_triage(db)
    return result


@router.post("/rebuild-triage")
async def trigger_rebuild_triage(db: AsyncSession = Depends(get_db)):
    """Force rebuild triage scoring."""
    count = await rebuild_triage(db)
    return {"triage_items": count}


# ══════════════════════════════════════════════════════════════════════════
# Identity Monitor endpoints
# ══════════════════════════════════════════════════════════════════════════

@router.get("/identities", response_model=list[MonitoredIdentityResponse])
async def list_monitored_identities(db: AsyncSession = Depends(get_db)):
    """List all monitored email identities."""
    return await list_identities(db)


@router.post("/identities", response_model=MonitoredIdentityResponse, status_code=201)
async def add_monitored_identity(
    body: MonitoredIdentityCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add an email address to the monitored list."""
    try:
        return await add_identity(db, body.email, body.label, body.owner)
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.delete("/identities/{identity_id}")
async def delete_monitored_identity(identity_id: str, db: AsyncSession = Depends(get_db)):
    """Remove a monitored identity and its breach records."""
    removed = await remove_identity(db, identity_id)
    if not removed:
        raise HTTPException(404, "Identity not found")
    return {"deleted": True}


@router.get("/identities/{identity_id}/breaches", response_model=list[BreachHitResponse])
async def get_identity_breach_hits(identity_id: str, db: AsyncSession = Depends(get_db)):
    """Get all breach hits for a specific identity."""
    return await get_identity_breaches(db, identity_id)


@router.post("/identities/check-all", response_model=BreachCheckResult)
async def check_all_monitored_identities(db: AsyncSession = Depends(get_db)):
    """Run HIBP breach check on all monitored identities (rate-limited)."""
    result = await check_all_identities(db)
    return result


@router.post("/identities/{identity_id}/check")
async def check_single_monitored_identity(identity_id: str, db: AsyncSession = Depends(get_db)):
    """Run HIBP breach check on a single identity."""
    ident_result = await db.execute(
        select(MonitoredIdentity).where(MonitoredIdentity.id == identity_id)
    )
    identity = ident_result.scalar_one_or_none()
    if not identity:
        raise HTTPException(404, "Identity not found")
    result = await check_single_identity(db, identity)
    return result


@router.get("/identities/summary", response_model=IdentitySummary)
async def get_identity_monitor_summary(db: AsyncSession = Depends(get_db)):
    """Dashboard summary for identity monitoring."""
    return await get_identity_summary(db)


@router.post("/password-check", response_model=PasswordCheckResponse)
async def check_password_exposure(
    body: PasswordCheckRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Check if a password has been exposed using k-anonymity.
    Client must send the SHA-1 hash of the password, never plaintext.
    Only the first 5 chars of the hash are sent to HIBP.
    """
    if len(body.sha1_hash) != 40:
        raise HTTPException(400, "Expected a 40-character SHA-1 hash")
    result = await check_password_hash(db, body.sha1_hash)
    return result
