"""
HIBP (Have I Been Pwned) connectors.
- Breach check: email → list of breaches
- Password k-anonymity: SHA-1 prefix → compromised count

All queries use the public HIBP API v3.
Password check uses k-anonymity (only SHA-1 prefix sent, full hash never leaves the server).
"""
import hashlib
import httpx
import structlog

logger = structlog.get_logger()

TIMEOUT = httpx.Timeout(15.0, connect=10.0)
HIBP_HEADERS = {
    "User-Agent": "RiskPlatform-BreachMonitor/1.0",
}

# ── Breach check (free, unauthenticated for single-email lookups) ─────────
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"


async def check_email_breaches(email: str, truncate: bool = False) -> list[dict]:
    """
    Check if an email appears in known breaches via HIBP.
    Free tier: single email lookups are rate-limited (~1 req/1.5s).
    Returns list of breach dicts with name, title, date, data classes, etc.
    """
    url = f"{HIBP_BREACHES_URL}/{email}"
    params = {"truncateResponse": "true" if truncate else "false"}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(url, headers=HIBP_HEADERS, params=params)

        if resp.status_code == 404:
            # Not found in any breach
            return []
        if resp.status_code == 429:
            retry_after = resp.headers.get("retry-after", "2")
            logger.warning("hibp_rate_limited", retry_after=retry_after, email=email)
            raise Exception(f"HIBP rate limited. Retry after {retry_after}s")
        if resp.status_code == 401:
            logger.warning("hibp_auth_required", email=email)
            raise Exception("HIBP API key required for this endpoint. Using fallback.")

        resp.raise_for_status()
        breaches = resp.json()

    results = []
    for b in breaches:
        results.append({
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "added_date": b.get("AddedDate"),
            "modified_date": b.get("ModifiedDate"),
            "pwn_count": b.get("PwnCount"),
            "description": b.get("Description"),
            "data_classes": b.get("DataClasses", []),
            "is_verified": b.get("IsVerified", False),
            "is_fabricated": b.get("IsFabricated", False),
            "is_sensitive": b.get("IsSensitive", False),
            "is_retired": b.get("IsRetired", False),
            "is_spam_list": b.get("IsSpamList", False),
            "is_subscription_free": b.get("IsSubscriptionFree", False),
            "logo_path": b.get("LogoPath"),
        })
    logger.info("hibp_email_checked", email=email, breaches_found=len(results))
    return results


# ── All breaches metadata (free, no auth) ─────────────────────────────────
HIBP_ALL_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


async def fetch_all_breaches() -> list[dict]:
    """Fetch the full list of known breaches from HIBP (metadata only, no emails)."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(HIBP_ALL_BREACHES_URL, headers=HIBP_HEADERS)
        resp.raise_for_status()
        return resp.json()


# ── Password k-anonymity check (free, unlimited) ─────────────────────────
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range"


async def check_password_compromised(password: str) -> dict:
    """
    Check if a password has been exposed in any breach using k-anonymity.

    How it works:
    1. SHA-1 hash the password
    2. Send only the first 5 characters to HIBP
    3. HIBP returns all hash suffixes matching that prefix
    4. We check locally if the full hash appears in the response

    The password NEVER leaves this function in any form that could be intercepted.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(f"{HIBP_PASSWORD_URL}/{prefix}")
        resp.raise_for_status()

    # Response is a text list: "SUFFIX:count\r\n"
    count = 0
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            break

    return {
        "sha1_prefix": prefix,
        "is_compromised": count > 0,
        "occurrence_count": count,
    }


async def check_password_by_hash(sha1_hash: str) -> dict:
    """
    Same k-anonymity check but accepts a pre-computed SHA-1 hash.
    Use this when the client hashes the password before sending.
    """
    sha1_hash = sha1_hash.upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(f"{HIBP_PASSWORD_URL}/{prefix}")
        resp.raise_for_status()

    count = 0
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            break

    return {
        "sha1_prefix": prefix,
        "is_compromised": count > 0,
        "occurrence_count": count,
    }
