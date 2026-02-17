"""
Connectors for free, reputable threat intelligence sources.
Each connector fetches data from a public API and returns normalized items.
"""
import httpx
import structlog
from datetime import datetime, timedelta, timezone

logger = structlog.get_logger()

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


# ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev() -> list[dict]:
    """Fetch CISA KEV catalog. Returns list of vulnerability dicts."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    logger.info("kev_fetched", count=len(vulns))
    results = []
    for v in vulns:
        results.append({
            "cve_id": v.get("cveID"),
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "short_description": v.get("shortDescription"),
            "required_action": v.get("requiredAction"),
            "due_date": v.get("dueDate"),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "notes": v.get("notes", ""),
        })
    return results


# ── FIRST EPSS (Exploit Prediction Scoring System) ───────────────────────
EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss_top(limit: int = 100, min_score: float = 0.5) -> list[dict]:
    """Fetch top CVEs by EPSS score. Returns list of EPSS dicts."""
    params = {
        "order": "!epss",
        "limit": limit,
    }
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        resp = await client.get(EPSS_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
    items = data.get("data", [])
    results = []
    for item in items:
        score = float(item.get("epss", 0))
        if score >= min_score:
            results.append({
                "cve_id": item.get("cve"),
                "epss_score": score,
                "epss_percentile": float(item.get("percentile", 0)),
                "date": item.get("date"),
            })
    logger.info("epss_fetched", count=len(results), min_score=min_score)
    return results


async def fetch_epss_for_cves(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for specific CVE IDs. Returns dict keyed by CVE ID."""
    if not cve_ids:
        return {}
    # EPSS API accepts comma-separated CVE list
    chunks = [cve_ids[i:i+30] for i in range(0, len(cve_ids), 30)]
    result = {}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for chunk in chunks:
            params = {"cve": ",".join(chunk)}
            try:
                resp = await client.get(EPSS_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    result[item["cve"]] = {
                        "epss_score": float(item.get("epss", 0)),
                        "epss_percentile": float(item.get("percentile", 0)),
                    }
            except Exception as e:
                logger.warning("epss_chunk_failed", error=str(e))
    return result


# ── NVD (National Vulnerability Database) ─────────────────────────────────
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_nvd_recent(days: int = 7, max_results: int = 100) -> list[dict]:
    """Fetch recently published/modified CVEs from NVD. Free tier = 5 req/30s."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(max_results, 200),
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        resp = await client.get(NVD_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        # Extract CVSS
        cvss_base = None
        cvss_vector = None
        metrics = cve.get("metrics", {})
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_base = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break
        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        results.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss_base": cvss_base,
            "cvss_vector": cvss_vector,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        })
    logger.info("nvd_fetched", count=len(results), days=days)
    return results


async def fetch_nvd_cve(cve_id: str) -> dict | None:
    """Fetch a single CVE from NVD."""
    params = {"cveId": cve_id}
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        resp = await client.get(NVD_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    cvss_base = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    for vk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        ml = metrics.get(vk, [])
        if ml:
            cd = ml[0].get("cvssData", {})
            cvss_base = cd.get("baseScore")
            cvss_vector = cd.get("vectorString")
            break
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    return {
        "cve_id": cve.get("id"),
        "description": desc,
        "cvss_base": cvss_base,
        "cvss_vector": cvss_vector,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


# ── BSI (German Federal Office for Information Security) ──────────────────
BSI_CERT_BUND_RSS = "https://wid.cert-bund.de/content/public/securityAdvisory/rss"


async def fetch_bsi_advisories() -> list[dict]:
    """Fetch BSI/CERT-Bund advisories via RSS feed, parsed as XML."""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(BSI_CERT_BUND_RSS)
        resp.raise_for_status()
        text = resp.text

    # Simple XML parsing without external dependency
    items = []
    import re
    for match in re.finditer(r"<item>(.*?)</item>", text, re.DOTALL):
        block = match.group(1)
        title = _xml_text(block, "title")
        link = _xml_text(block, "link")
        desc = _xml_text(block, "description")
        pub_date = _xml_text(block, "pubDate")
        # Extract advisory ID from link (e.g. WID-SEC-2024-XXXX)
        adv_id_match = re.search(r"(WID-SEC-\d{4}-\d+)", link or "")
        adv_id = adv_id_match.group(1) if adv_id_match else None

        # Infer severity from title keywords
        severity = "medium"
        title_lower = (title or "").lower()
        if "kritisch" in title_lower or "critical" in title_lower:
            severity = "critical"
        elif "hoch" in title_lower or "high" in title_lower:
            severity = "high"
        elif "niedrig" in title_lower or "low" in title_lower:
            severity = "low"

        # Extract CVE IDs from description
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", desc or "")

        items.append({
            "advisory_id": adv_id or f"BSI-{hash(title) % 100000:05d}",
            "issuer": "CERT-Bund",
            "severity": severity,
            "title": title or "Unknown",
            "summary": desc,
            "cve_ids": list(set(cve_ids)),
            "source_url": link,
            "published_at": pub_date,
        })
    logger.info("bsi_fetched", count=len(items))
    return items


def _xml_text(block: str, tag: str) -> str | None:
    """Extract text content from a simple XML tag."""
    import re
    # Handle CDATA
    m = re.search(rf"<{tag}[^>]*>\s*<!\[CDATA\[(.*?)\]\]>\s*</{tag}>", block, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", block, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None
