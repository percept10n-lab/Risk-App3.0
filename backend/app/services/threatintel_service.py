"""
Threat intelligence service — orchestrates connectors, scoring, and triage.
"""
import time
import structlog
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.threatintel import CVEItem, AdvisoryItem, TriageItem, ConnectorStatus
from app.services.threatintel_connectors import (
    fetch_kev, fetch_epss_top, fetch_epss_for_cves,
    fetch_nvd_recent, fetch_bsi_advisories,
)

logger = structlog.get_logger()

# ── Scoring configuration ─────────────────────────────────────────────────
EPSS_GATE = 0.7
CVSS_GATE = 7.5
HIGH_SEVERITIES = {"high", "critical"}
KEV_WEIGHT = 55
KEV_FLOOR = 70
EPSS_MAX_WEIGHT = 20
CVSS_MAX_WEIGHT = 15
NO_PATCH_BONUS = 5
CORROBORATION_BONUS = 5
MAX_TRIAGE = 12


def compute_urgency_score(
    kev_listed: bool = False,
    epss_score: float = 0,
    cvss_base: float = 0,
    patch_available: bool = True,
    advisory_severity: str | None = None,
    source_count: int = 1,
) -> int | None:
    """
    Compute UrgencyScore (0-100) with hard gates.
    Returns None if item doesn't pass any gate.
    """
    # Check gates
    gate_kev = kev_listed
    gate_epss_cvss = epss_score >= EPSS_GATE and cvss_base >= CVSS_GATE
    gate_advisory = advisory_severity in HIGH_SEVERITIES

    if not (gate_kev or gate_epss_cvss or gate_advisory):
        return None

    score = 0

    # KEV weight
    if kev_listed:
        score += KEV_WEIGHT

    # EPSS weight (0-20, scaled)
    if epss_score > 0:
        score += int(epss_score * EPSS_MAX_WEIGHT)

    # CVSS weight (0-15, scaled from 0-10)
    if cvss_base > 0:
        score += int((cvss_base / 10.0) * CVSS_MAX_WEIGHT)

    # Patch unavailability bonus
    if not patch_available:
        score += NO_PATCH_BONUS

    # Cross-source corroboration
    if source_count >= 2:
        score += CORROBORATION_BONUS

    # KEV floor
    if kev_listed:
        score = max(score, KEV_FLOOR)

    return min(score, 100)


def determine_why_here(
    kev_listed: bool, epss_score: float, cvss_base: float,
    advisory_severity: str | None, patch_available: bool,
) -> str:
    """Generate a concise 'why here' explanation."""
    reasons = []
    if kev_listed:
        reasons.append("Listed in CISA KEV")
    if epss_score >= EPSS_GATE:
        reasons.append(f"EPSS {epss_score:.2f}")
    if cvss_base >= CVSS_GATE:
        reasons.append(f"CVSS {cvss_base:.1f}")
    if advisory_severity in HIGH_SEVERITIES:
        reasons.append(f"Advisory severity: {advisory_severity}")
    if not patch_available:
        reasons.append("No patch available")
    return " · ".join(reasons) if reasons else "Meets triage threshold"


# ── Connector orchestration ───────────────────────────────────────────────

async def _update_connector(db: AsyncSession, name: str, display: str, url: str):
    """Ensure connector status row exists."""
    result = await db.execute(select(ConnectorStatus).where(ConnectorStatus.connector_name == name))
    cs = result.scalar_one_or_none()
    if not cs:
        cs = ConnectorStatus(
            connector_name=name,
            display_name=display,
            source_url=url,
        )
        db.add(cs)
        await db.flush()
    return cs


async def _mark_success(db: AsyncSession, name: str, count: int):
    result = await db.execute(select(ConnectorStatus).where(ConnectorStatus.connector_name == name))
    cs = result.scalar_one_or_none()
    if cs:
        cs.last_success = datetime.now(timezone.utc)
        cs.last_attempt = datetime.now(timezone.utc)
        cs.items_ingested = count
        cs.last_error = None


async def _mark_error(db: AsyncSession, name: str, error: str):
    result = await db.execute(select(ConnectorStatus).where(ConnectorStatus.connector_name == name))
    cs = result.scalar_one_or_none()
    if cs:
        cs.last_attempt = datetime.now(timezone.utc)
        cs.last_error = error
        cs.error_count = (cs.error_count or 0) + 1


async def ingest_kev(db: AsyncSession) -> dict:
    """Ingest CISA KEV data."""
    t0 = time.monotonic()
    name = "cisa_kev"
    await _update_connector(db, name, "CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    errors = []
    count = 0
    try:
        items = await fetch_kev()
        for item in items:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            result = await db.execute(select(CVEItem).where(CVEItem.cve_id == cve_id))
            existing = result.scalar_one_or_none()
            if existing:
                existing.kev_listed = True
                existing.kev_date_added = _parse_date(item.get("date_added"))
                existing.kev_due_date = _parse_date(item.get("due_date"))
                existing.kev_notes = item.get("notes")
                existing.vendor_project = existing.vendor_project or item.get("vendor_project")
                existing.product = existing.product or item.get("product")
                existing.description = existing.description or item.get("short_description")
                prov = existing.provenance or {}
                prov["kev"] = {"fetched": datetime.now(timezone.utc).isoformat()}
                existing.provenance = prov
            else:
                cve = CVEItem(
                    cve_id=cve_id,
                    vendor_project=item.get("vendor_project"),
                    product=item.get("product"),
                    product_summary=f"{item.get('vendor_project', '')} {item.get('product', '')}".strip(),
                    description=item.get("short_description"),
                    kev_listed=True,
                    kev_date_added=_parse_date(item.get("date_added")),
                    kev_due_date=_parse_date(item.get("due_date")),
                    kev_notes=item.get("notes"),
                    provenance={"kev": {"fetched": datetime.now(timezone.utc).isoformat()}},
                )
                db.add(cve)
            count += 1
        await _mark_success(db, name, count)
    except Exception as e:
        errors.append(str(e))
        await _mark_error(db, name, str(e))
        logger.error("kev_ingest_failed", error=str(e))
    return {"connector": name, "items_ingested": count, "errors": errors, "duration_ms": int((time.monotonic() - t0) * 1000)}


async def ingest_epss(db: AsyncSession) -> dict:
    """Ingest FIRST EPSS top scores."""
    t0 = time.monotonic()
    name = "first_epss"
    await _update_connector(db, name, "FIRST EPSS", "https://www.first.org/epss/")
    errors = []
    count = 0
    try:
        items = await fetch_epss_top(limit=100, min_score=0.3)
        for item in items:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            result = await db.execute(select(CVEItem).where(CVEItem.cve_id == cve_id))
            existing = result.scalar_one_or_none()
            if existing:
                existing.epss_score = item["epss_score"]
                existing.epss_percentile = item["epss_percentile"]
                prov = existing.provenance or {}
                prov["epss"] = {"fetched": datetime.now(timezone.utc).isoformat()}
                existing.provenance = prov
            else:
                cve = CVEItem(
                    cve_id=cve_id,
                    epss_score=item["epss_score"],
                    epss_percentile=item["epss_percentile"],
                    provenance={"epss": {"fetched": datetime.now(timezone.utc).isoformat()}},
                )
                db.add(cve)
            count += 1
        await _mark_success(db, name, count)
    except Exception as e:
        errors.append(str(e))
        await _mark_error(db, name, str(e))
        logger.error("epss_ingest_failed", error=str(e))
    return {"connector": name, "items_ingested": count, "errors": errors, "duration_ms": int((time.monotonic() - t0) * 1000)}


async def ingest_nvd(db: AsyncSession, days: int = 7) -> dict:
    """Ingest recent NVD CVEs."""
    t0 = time.monotonic()
    name = "nvd"
    await _update_connector(db, name, "NVD", "https://nvd.nist.gov/")
    errors = []
    count = 0
    try:
        items = await fetch_nvd_recent(days=days, max_results=100)
        for item in items:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            result = await db.execute(select(CVEItem).where(CVEItem.cve_id == cve_id))
            existing = result.scalar_one_or_none()
            if existing:
                if item.get("cvss_base") and not existing.cvss_base:
                    existing.cvss_base = item["cvss_base"]
                    existing.cvss_vector = item.get("cvss_vector")
                if item.get("description") and not existing.description:
                    existing.description = item["description"]
                prov = existing.provenance or {}
                prov["nvd"] = {"fetched": datetime.now(timezone.utc).isoformat()}
                existing.provenance = prov
            else:
                cve = CVEItem(
                    cve_id=cve_id,
                    description=item.get("description"),
                    cvss_base=item.get("cvss_base"),
                    cvss_vector=item.get("cvss_vector"),
                    provenance={"nvd": {"fetched": datetime.now(timezone.utc).isoformat()}},
                )
                db.add(cve)
            count += 1
        await _mark_success(db, name, count)
    except Exception as e:
        errors.append(str(e))
        await _mark_error(db, name, str(e))
        logger.error("nvd_ingest_failed", error=str(e))
    return {"connector": name, "items_ingested": count, "errors": errors, "duration_ms": int((time.monotonic() - t0) * 1000)}


async def ingest_bsi(db: AsyncSession) -> dict:
    """Ingest BSI/CERT-Bund advisories."""
    t0 = time.monotonic()
    name = "cert_bund"
    await _update_connector(db, name, "CERT-Bund / BSI", "https://wid.cert-bund.de/")
    errors = []
    count = 0
    try:
        items = await fetch_bsi_advisories()
        for item in items:
            adv_id = item.get("advisory_id")
            if not adv_id:
                continue
            result = await db.execute(select(AdvisoryItem).where(AdvisoryItem.advisory_id == adv_id))
            existing = result.scalar_one_or_none()
            if existing:
                existing.severity = item.get("severity", existing.severity)
                existing.title = item.get("title", existing.title)
                existing.summary = item.get("summary", existing.summary)
                existing.cve_ids = item.get("cve_ids", existing.cve_ids)
                existing.source_url = item.get("source_url", existing.source_url)
            else:
                adv = AdvisoryItem(
                    advisory_id=adv_id,
                    issuer=item.get("issuer", "CERT-Bund"),
                    severity=item.get("severity", "medium"),
                    title=item.get("title", "Unknown"),
                    summary=item.get("summary"),
                    cve_ids=item.get("cve_ids", []),
                    source_url=item.get("source_url"),
                    published_at=_parse_rss_date(item.get("published_at")),
                    references=[item.get("source_url")] if item.get("source_url") else [],
                    provenance={"cert_bund": {"fetched": datetime.now(timezone.utc).isoformat()}},
                )
                db.add(adv)
            count += 1
        await _mark_success(db, name, count)
    except Exception as e:
        errors.append(str(e))
        await _mark_error(db, name, str(e))
        logger.error("bsi_ingest_failed", error=str(e))
    return {"connector": name, "items_ingested": count, "errors": errors, "duration_ms": int((time.monotonic() - t0) * 1000)}


async def enrich_epss(db: AsyncSession) -> int:
    """Enrich CVE items that are missing EPSS scores."""
    result = await db.execute(
        select(CVEItem).where(CVEItem.epss_score.is_(None)).limit(100)
    )
    cves = result.scalars().all()
    if not cves:
        return 0
    cve_ids = [c.cve_id for c in cves]
    epss_data = await fetch_epss_for_cves(cve_ids)
    enriched = 0
    for cve in cves:
        if cve.cve_id in epss_data:
            cve.epss_score = epss_data[cve.cve_id]["epss_score"]
            cve.epss_percentile = epss_data[cve.cve_id]["epss_percentile"]
            prov = cve.provenance or {}
            prov["epss"] = {"fetched": datetime.now(timezone.utc).isoformat()}
            cve.provenance = prov
            enriched += 1
    return enriched


# ── Triage computation ────────────────────────────────────────────────────

async def rebuild_triage(db: AsyncSession) -> int:
    """Rebuild the triage list from current CVE + advisory data."""
    await db.execute(delete(TriageItem))

    candidates: list[TriageItem] = []

    # Score CVEs
    result = await db.execute(select(CVEItem))
    cves = result.scalars().all()
    for cve in cves:
        source_count = len(cve.provenance or {})
        score = compute_urgency_score(
            kev_listed=cve.kev_listed,
            epss_score=cve.epss_score or 0,
            cvss_base=cve.cvss_base or 0,
            patch_available=cve.patch_available,
            source_count=source_count,
        )
        if score is None:
            continue

        item_type = "exploited_cve" if cve.kev_listed else "high_risk_cve"
        badges = list((cve.provenance or {}).keys())
        if cve.kev_listed and "cisa_kev" not in [b.lower().replace("-", "_") for b in badges]:
            badges.append("CISA-KEV")

        why = determine_why_here(
            cve.kev_listed, cve.epss_score or 0, cve.cvss_base or 0,
            None, cve.patch_available,
        )

        candidates.append(TriageItem(
            item_type=item_type,
            primary_id=cve.cve_id,
            title=cve.description[:200] if cve.description else cve.product_summary or cve.cve_id,
            why_here=why,
            urgency_score=score,
            source_badges=badges,
            deep_link=f"/vulnerabilities?cve={cve.cve_id}",
            extra_data={
                "cvss_base": cve.cvss_base,
                "epss_score": cve.epss_score,
                "kev_listed": cve.kev_listed,
                "patch_available": cve.patch_available,
                "vendor_project": cve.vendor_project,
                "product": cve.product,
            },
        ))

    # Score advisories
    result = await db.execute(select(AdvisoryItem))
    advisories = result.scalars().all()
    for adv in advisories:
        score = compute_urgency_score(advisory_severity=adv.severity)
        if score is None:
            continue
        candidates.append(TriageItem(
            item_type="advisory",
            primary_id=adv.advisory_id,
            title=adv.title,
            why_here=f"Advisory severity: {adv.severity} ({adv.issuer})",
            urgency_score=score,
            source_badges=[adv.issuer],
            deep_link=f"/advisories?id={adv.advisory_id}",
            extra_data={
                "issuer": adv.issuer,
                "severity": adv.severity,
                "cve_ids": adv.cve_ids,
            },
        ))

    # Sort and take top N
    candidates.sort(key=lambda x: (-x.urgency_score, x.primary_id))
    for item in candidates[:MAX_TRIAGE]:
        db.add(item)

    logger.info("triage_rebuilt", total_candidates=len(candidates), kept=min(len(candidates), MAX_TRIAGE))
    return min(len(candidates), MAX_TRIAGE)


# ── Full ingest pipeline ─────────────────────────────────────────────────

async def run_full_ingest(db: AsyncSession) -> list[dict]:
    """Run all connectors and rebuild triage."""
    results = []
    results.append(await ingest_kev(db))
    await db.flush()
    results.append(await ingest_epss(db))
    await db.flush()
    results.append(await ingest_nvd(db))
    await db.flush()
    results.append(await ingest_bsi(db))
    await db.flush()
    # Enrich missing EPSS
    enriched = await enrich_epss(db)
    logger.info("epss_enrichment", enriched=enriched)
    # Rebuild triage
    triage_count = await rebuild_triage(db)
    results.append({"connector": "triage_engine", "items_ingested": triage_count, "errors": [], "duration_ms": 0})
    return results


# ── Query helpers ─────────────────────────────────────────────────────────

async def get_dashboard_data(db: AsyncSession, hours: int = 72) -> dict:
    """Get all data for the landing page."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Triage items
    result = await db.execute(
        select(TriageItem).order_by(TriageItem.urgency_score.desc()).limit(MAX_TRIAGE)
    )
    triage = result.scalars().all()

    # KEV latest
    result = await db.execute(
        select(CVEItem).where(CVEItem.kev_listed == True).order_by(CVEItem.kev_date_added.desc()).limit(8)
    )
    kev_latest = result.scalars().all()

    # EPSS top
    result = await db.execute(
        select(CVEItem).where(CVEItem.epss_score.isnot(None)).order_by(CVEItem.epss_score.desc()).limit(8)
    )
    epss_top = result.scalars().all()

    # Latest advisories
    result = await db.execute(
        select(AdvisoryItem).order_by(AdvisoryItem.created_at.desc()).limit(10)
    )
    advisories = result.scalars().all()

    # Connectors
    result = await db.execute(select(ConnectorStatus).order_by(ConnectorStatus.connector_name))
    connectors = result.scalars().all()

    # Counters
    now = datetime.now(timezone.utc)
    cutoff_72h = now - timedelta(hours=72)
    cutoff_7d = now - timedelta(days=7)

    kev_7d = await db.scalar(
        select(func.count(CVEItem.id)).where(
            and_(CVEItem.kev_listed == True, CVEItem.kev_date_added >= cutoff_7d)
        )
    ) or 0
    exploited_72h = await db.scalar(
        select(func.count(CVEItem.id)).where(
            and_(CVEItem.kev_listed == True, CVEItem.updated_at >= cutoff_72h)
        )
    ) or 0
    high_epss_72h = await db.scalar(
        select(func.count(CVEItem.id)).where(
            and_(CVEItem.epss_score >= EPSS_GATE, CVEItem.updated_at >= cutoff_72h)
        )
    ) or 0
    critical_adv_72h = await db.scalar(
        select(func.count(AdvisoryItem.id)).where(
            and_(AdvisoryItem.severity.in_(["critical", "high"]), AdvisoryItem.created_at >= cutoff_72h)
        )
    ) or 0
    national_adv_72h = await db.scalar(
        select(func.count(AdvisoryItem.id)).where(
            and_(AdvisoryItem.issuer.in_(["BSI", "CERT-Bund", "ENISA"]), AdvisoryItem.created_at >= cutoff_72h)
        )
    ) or 0
    total_cves = await db.scalar(select(func.count(CVEItem.id))) or 0
    total_advisories = await db.scalar(select(func.count(AdvisoryItem.id))) or 0

    return {
        "triage": triage,
        "kev_latest": kev_latest,
        "epss_top": epss_top,
        "advisories_latest": advisories,
        "connectors": connectors,
        "counters": {
            "kev_additions_7d": kev_7d,
            "exploited_wild_72h": exploited_72h,
            "high_epss_72h": high_epss_72h,
            "critical_advisories_72h": critical_adv_72h,
            "national_advisories_72h": national_adv_72h,
            "total_cves": total_cves,
            "total_advisories": total_advisories,
        },
    }


# ── Utilities ─────────────────────────────────────────────────────────────

def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


def _parse_rss_date(s: str | None) -> datetime | None:
    if not s:
        return None
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(s)
    except Exception:
        return None
