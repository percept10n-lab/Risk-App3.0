"""
Identity monitoring service — manages monitored emails, runs breach checks,
computes severity, and tracks results with provenance.
"""
import asyncio
import time
import structlog
from datetime import datetime, timezone
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threatintel import (
    MonitoredIdentity, BreachHit, PasswordCheckResult, ConnectorStatus,
)
from app.services.hibp_connector import (
    check_email_breaches, check_password_compromised, check_password_by_hash,
)

logger = structlog.get_logger()

# ── Severity scoring for breaches ─────────────────────────────────────────

# Data classes that indicate high severity
CRITICAL_DATA = {"Passwords", "Credit cards", "Bank account numbers", "Social security numbers"}
HIGH_DATA = {"Password hints", "Security questions and answers", "Auth tokens",
             "Passport numbers", "Government issued IDs"}
MEDIUM_DATA = {"Email addresses", "Phone numbers", "Physical addresses",
               "Dates of birth", "IP addresses", "Employers"}


def compute_breach_severity(data_classes: list[str], is_verified: bool, is_sensitive: bool) -> str:
    """Compute breach severity based on exposed data classes."""
    classes_set = set(data_classes)

    if classes_set & CRITICAL_DATA:
        return "critical"
    if classes_set & HIGH_DATA or is_sensitive:
        return "high"
    if classes_set & MEDIUM_DATA and is_verified:
        return "medium"
    return "low"


# ── Identity CRUD ─────────────────────────────────────────────────────────

async def add_identity(db: AsyncSession, email: str, label: str | None = None, owner: str | None = None) -> MonitoredIdentity:
    """Add an email to the monitored list."""
    existing = await db.execute(select(MonitoredIdentity).where(MonitoredIdentity.email == email))
    if existing.scalar_one_or_none():
        raise ValueError(f"Email {email} is already monitored")
    identity = MonitoredIdentity(email=email, label=label, owner=owner)
    db.add(identity)
    await db.flush()
    return identity


async def remove_identity(db: AsyncSession, identity_id: str) -> bool:
    """Remove an identity and its breach hits."""
    result = await db.execute(select(MonitoredIdentity).where(MonitoredIdentity.id == identity_id))
    identity = result.scalar_one_or_none()
    if not identity:
        return False
    # Delete breach hits
    await db.execute(delete(BreachHit).where(BreachHit.identity_id == identity_id))
    await db.delete(identity)
    return True


async def list_identities(db: AsyncSession) -> list[MonitoredIdentity]:
    """List all monitored identities."""
    result = await db.execute(
        select(MonitoredIdentity).order_by(MonitoredIdentity.email)
    )
    return list(result.scalars().all())


async def get_identity_breaches(db: AsyncSession, identity_id: str) -> list[BreachHit]:
    """Get all breach hits for an identity."""
    result = await db.execute(
        select(BreachHit).where(BreachHit.identity_id == identity_id)
        .order_by(BreachHit.severity.desc(), BreachHit.breach_date.desc())
    )
    return list(result.scalars().all())


# ── Breach check pipeline ─────────────────────────────────────────────────

async def _ensure_hibp_connector(db: AsyncSession):
    """Ensure HIBP connector status row exists."""
    result = await db.execute(
        select(ConnectorStatus).where(ConnectorStatus.connector_name == "hibp")
    )
    cs = result.scalar_one_or_none()
    if not cs:
        cs = ConnectorStatus(
            connector_name="hibp",
            display_name="Have I Been Pwned",
            source_url="https://haveibeenpwned.com/",
        )
        db.add(cs)
        await db.flush()
    return cs


async def check_single_identity(db: AsyncSession, identity: MonitoredIdentity) -> dict:
    """Check a single email against HIBP and store results."""
    new_breaches = 0
    errors = []

    try:
        breaches = await check_email_breaches(identity.email)

        for b in breaches:
            # Check if this breach is already recorded
            existing = await db.execute(
                select(BreachHit).where(
                    BreachHit.identity_id == identity.id,
                    BreachHit.breach_name == b["name"],
                )
            )
            if existing.scalar_one_or_none():
                continue  # Already known

            severity = compute_breach_severity(
                b.get("data_classes", []),
                b.get("is_verified", False),
                b.get("is_sensitive", False),
            )

            hit = BreachHit(
                identity_id=identity.id,
                email=identity.email,
                breach_name=b["name"],
                breach_title=b.get("title"),
                breach_domain=b.get("domain"),
                breach_date=_parse_date(b.get("breach_date")),
                added_date=_parse_datetime(b.get("added_date")),
                data_classes=b.get("data_classes", []),
                description=b.get("description"),
                is_verified=b.get("is_verified", False),
                is_sensitive=b.get("is_sensitive", False),
                severity=severity,
                source="HIBP",
                provenance={"hibp": {"checked": datetime.now(timezone.utc).isoformat()}},
            )
            db.add(hit)
            new_breaches += 1

        # Update identity
        identity.last_checked = datetime.now(timezone.utc)
        identity.breach_count = await db.scalar(
            select(func.count(BreachHit.id)).where(BreachHit.identity_id == identity.id)
        ) or 0

    except Exception as e:
        errors.append(str(e))
        logger.error("hibp_check_failed", email=identity.email, error=str(e))

    return {"email": identity.email, "new_breaches": new_breaches, "errors": errors}


async def check_all_identities(db: AsyncSession) -> dict:
    """Check all monitored identities. Rate-limited to respect HIBP's ~1 req/1.5s."""
    t0 = time.monotonic()
    await _ensure_hibp_connector(db)

    identities = await list_identities(db)
    total_new = 0
    all_errors = []

    for i, identity in enumerate(identities):
        if not identity.enabled:
            continue
        result = await check_single_identity(db, identity)
        total_new += result["new_breaches"]
        all_errors.extend(result["errors"])
        await db.flush()

        # Rate limiting: ~1.6s between requests to respect HIBP free tier
        if i < len(identities) - 1:
            await asyncio.sleep(1.6)

    # Update connector status
    cs_result = await db.execute(
        select(ConnectorStatus).where(ConnectorStatus.connector_name == "hibp")
    )
    cs = cs_result.scalar_one_or_none()
    if cs:
        cs.last_attempt = datetime.now(timezone.utc)
        if not all_errors:
            cs.last_success = datetime.now(timezone.utc)
            cs.last_error = None
        else:
            cs.last_error = "; ".join(all_errors[:3])
            cs.error_count = (cs.error_count or 0) + 1
        cs.items_ingested = await db.scalar(select(func.count(BreachHit.id))) or 0

    duration = int((time.monotonic() - t0) * 1000)
    return {
        "identities_checked": len([i for i in identities if i.enabled]),
        "new_breaches": total_new,
        "errors": all_errors,
        "duration_ms": duration,
    }


# ── Password check ────────────────────────────────────────────────────────

async def check_password(db: AsyncSession, password: str, checked_by: str | None = None) -> dict:
    """Check a password via k-anonymity. Password is hashed locally, only prefix sent."""
    result = await check_password_compromised(password)

    # Log the check (never store the password itself)
    record = PasswordCheckResult(
        sha1_prefix=result["sha1_prefix"],
        is_compromised=result["is_compromised"],
        occurrence_count=result["occurrence_count"],
        checked_by=checked_by,
    )
    db.add(record)

    return result


async def check_password_hash(db: AsyncSession, sha1_hash: str, checked_by: str | None = None) -> dict:
    """Check a pre-computed SHA-1 hash via k-anonymity."""
    result = await check_password_by_hash(sha1_hash)

    record = PasswordCheckResult(
        sha1_prefix=result["sha1_prefix"],
        is_compromised=result["is_compromised"],
        occurrence_count=result["occurrence_count"],
        checked_by=checked_by,
    )
    db.add(record)

    return result


# ── Dashboard summary ─────────────────────────────────────────────────────

async def get_identity_summary(db: AsyncSession) -> dict:
    """Summary data for landing page integration."""
    total_identities = await db.scalar(select(func.count(MonitoredIdentity.id))) or 0
    total_breaches = await db.scalar(select(func.count(BreachHit.id))) or 0
    critical_breaches = await db.scalar(
        select(func.count(BreachHit.id)).where(BreachHit.severity == "critical")
    ) or 0
    high_breaches = await db.scalar(
        select(func.count(BreachHit.id)).where(BreachHit.severity == "high")
    ) or 0
    exposed_identities = await db.scalar(
        select(func.count(MonitoredIdentity.id)).where(MonitoredIdentity.breach_count > 0)
    ) or 0

    # Latest breaches
    result = await db.execute(
        select(BreachHit).order_by(BreachHit.created_at.desc()).limit(5)
    )
    latest = list(result.scalars().all())

    return {
        "total_identities": total_identities,
        "total_breaches": total_breaches,
        "critical_breaches": critical_breaches,
        "high_breaches": high_breaches,
        "exposed_identities": exposed_identities,
        "latest_breaches": latest,
    }


# ── Helpers ───────────────────────────────────────────────────────────────

def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


def _parse_datetime(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
