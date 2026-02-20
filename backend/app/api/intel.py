import re
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func as sa_func

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.threat import Threat
from app.models.risk import Risk
from app.models.mitre_mapping import MitreMapping
from app.config import settings

import httpx
import structlog

logger = structlog.get_logger()

# -- Singleton feed cache for reuse across endpoints --
_feed_cache = None


def _get_feed_cache():
    global _feed_cache
    if _feed_cache is None:
        from mcp_servers.exploit_exposure.feeds import ThreatFeedCache
        _feed_cache = ThreatFeedCache(
            mode=settings.threat_feed_mode,
            cache_ttl=settings.threat_feed_cache_ttl,
        )
    return _feed_cache


def _get_ioc_client():
    from mcp_servers.exploit_exposure.ioc_feeds import IoCFeedClient
    return IoCFeedClient()


def _get_ip_reputation_client():
    from mcp_servers.exploit_exposure.ip_reputation import IPReputationClient
    return IPReputationClient(
        abuseipdb_key=settings.abuseipdb_api_key,
        greynoise_key=settings.greynoise_api_key,
        otx_key=settings.alienvault_otx_api_key,
    )

router = APIRouter()

# ─── RSS Feed Cache ──────────────────────────────────────────────────────────
_news_cache: dict = {"articles": [], "fetched_at": None, "source_count": 0}
_news_cache_ttl = 1800  # 30 minutes
_news_cache_time = 0.0

RSS_FEEDS = [
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
]

ISO27001_KEYWORD_MAP = {
    "ransomware": [
        {"control": "A.12.2", "name": "Malware Protection", "recommendation": "Ensure anti-malware controls are active and up-to-date on all endpoints."},
        {"control": "A.12.3", "name": "Backup", "recommendation": "Verify backup integrity and test restore procedures. Ensure air-gapped backups exist."},
    ],
    "data breach": [
        {"control": "A.18.1.4", "name": "Privacy and Protection of PII", "recommendation": "Review data classification and ensure encryption at rest and in transit."},
        {"control": "A.16.1", "name": "Incident Management", "recommendation": "Verify incident response plan is current and conduct a tabletop exercise."},
    ],
    "phishing": [
        {"control": "A.7.2.2", "name": "Information Security Awareness Training", "recommendation": "Conduct phishing awareness training for all users."},
        {"control": "A.9.4.2", "name": "Secure Log-on Procedures", "recommendation": "Enable MFA on all accounts, especially admin and email."},
    ],
    "vulnerability": [
        {"control": "A.12.6", "name": "Technical Vulnerability Management", "recommendation": "Run vulnerability scans and apply patches within SLA windows."},
    ],
    "cve": [
        {"control": "A.12.6", "name": "Technical Vulnerability Management", "recommendation": "Check if any disclosed CVEs affect your assets and prioritize patching."},
    ],
    "patch": [
        {"control": "A.12.6", "name": "Technical Vulnerability Management", "recommendation": "Review patch management processes and ensure timely deployment."},
    ],
    "iot": [
        {"control": "A.13.1", "name": "Network Security Management", "recommendation": "Segment IoT devices on separate VLANs with restricted access."},
        {"control": "A.14.1.2", "name": "Securing Application Services", "recommendation": "Disable unnecessary services and change default credentials on IoT devices."},
    ],
    "smart home": [
        {"control": "A.13.1", "name": "Network Security Management", "recommendation": "Isolate smart home devices from critical network segments."},
    ],
    "router": [
        {"control": "A.13.1", "name": "Network Security Management", "recommendation": "Ensure router firmware is up-to-date and admin interfaces are not exposed."},
    ],
    "firmware": [
        {"control": "A.12.6", "name": "Technical Vulnerability Management", "recommendation": "Check for firmware updates on all network devices and appliances."},
    ],
    "credential": [
        {"control": "A.9.2.4", "name": "Management of Secret Authentication Information", "recommendation": "Enforce strong password policies and enable MFA everywhere."},
    ],
    "password": [
        {"control": "A.9.2.4", "name": "Management of Secret Authentication Information", "recommendation": "Review password policies, rotate compromised credentials immediately."},
    ],
    "zero-day": [
        {"control": "A.12.6", "name": "Technical Vulnerability Management", "recommendation": "Monitor vendor advisories and apply mitigations for zero-day exploits immediately."},
    ],
    "malware": [
        {"control": "A.12.2", "name": "Malware Protection", "recommendation": "Update malware signatures and scan all endpoints."},
    ],
}

HOME_NETWORK_RISK_MAP = {
    "ransomware": "Ransomware could encrypt NAS/file shares on your home network. Ensure backups are air-gapped and test restore procedures.",
    "router": "Unpatched router firmware exposes all connected devices. Check for updates on your router admin panel.",
    "firmware": "Unpatched firmware on network devices could allow attackers to gain persistent access to your network.",
    "iot": "Compromised IoT devices could be used as botnet nodes or for lateral movement within your home network.",
    "smart home": "Smart home devices with weak security can be entry points for attackers to access your entire network.",
    "credential": "Default or weak credentials on home devices enable unauthorized access. Change all default passwords.",
    "password": "Weak or reused passwords across home network services create risk of credential stuffing attacks.",
    "phishing": "Phishing emails could compromise credentials for home network admin interfaces and cloud services.",
    "data breach": "Leaked credentials from data breaches may include passwords used on your home network devices and services.",
    "vpn": "VPN vulnerabilities could expose your home network to remote attacks. Keep VPN software updated.",
    "dns": "DNS hijacking could redirect your home network traffic to malicious servers. Use encrypted DNS (DoH/DoT).",
    "zero-day": "Zero-day vulnerabilities may affect software and devices on your home network before patches are available. Monitor advisories.",
    "malware": "Malware could spread across devices on your home network. Ensure endpoint protection is active on all devices.",
}


def _strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    return re.sub(r'<[^>]+>', '', text).strip()


def _match_keywords(text: str) -> tuple[list[dict], str]:
    """Match article text against keyword maps for ISO 27001 controls and home risk."""
    text_lower = text.lower()
    controls = []
    seen_controls = set()
    home_risk = ""

    for keyword, keyword_controls in ISO27001_KEYWORD_MAP.items():
        if keyword in text_lower:
            for ctrl in keyword_controls:
                if ctrl["control"] not in seen_controls:
                    controls.append(ctrl)
                    seen_controls.add(ctrl["control"])

    if not controls:
        controls = [{"control": "A.5.1", "name": "Information Security Policies", "recommendation": "Review your security policies in light of emerging threats."}]

    for keyword, risk_text in HOME_NETWORK_RISK_MAP.items():
        if keyword in text_lower:
            home_risk = risk_text
            break

    if not home_risk:
        home_risk = "Monitor your home network for indicators of compromise related to this threat."

    return controls, home_risk


def _extract_tag(item_xml: str, tag: str) -> str:
    """Extract text content from an XML/RSS tag, handling CDATA sections."""
    # Match <tag>...<![CDATA[...]]>...</tag> or <tag>text</tag>
    pattern = re.compile(
        rf'<{tag}[^>]*>(?:\s*<!\[CDATA\[(.*?)\]\]>\s*|(.*?))</{tag}>',
        re.DOTALL
    )
    m = pattern.search(item_xml)
    if not m:
        return ""
    raw = m.group(1) if m.group(1) is not None else (m.group(2) or "")
    return raw.strip()


async def _fetch_rss_feed(client: httpx.AsyncClient, source: str, url: str) -> list[dict]:
    """Fetch and parse a single RSS feed using regex for maximum tolerance."""
    articles = []
    try:
        resp = await client.get(url, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text

        # Split into <item>...</item> blocks
        item_pattern = re.compile(r'<item\b[^>]*>(.*?)</item>', re.DOTALL)
        items = item_pattern.findall(text)

        for item_xml in items[:10]:
            title = _strip_html(_extract_tag(item_xml, "title"))
            if not title:
                continue

            link = _extract_tag(item_xml, "link")
            published = _extract_tag(item_xml, "pubDate")
            if not published:
                published = _extract_tag(item_xml, "published")

            raw_desc = _extract_tag(item_xml, "description")
            if not raw_desc:
                raw_desc = _extract_tag(item_xml, "summary")
            summary = _strip_html(raw_desc) if raw_desc else ""
            if len(summary) > 300:
                summary = summary[:297] + "..."

            combined_text = f"{title} {summary}"
            iso_controls, home_risk = _match_keywords(combined_text)

            articles.append({
                "title": title,
                "link": link,
                "source": source,
                "published": published,
                "summary": summary,
                "iso27001_controls": iso_controls,
                "home_network_risk": home_risk,
            })
    except Exception as e:
        logger.warning("Failed to fetch RSS feed", source=source, url=url, error=str(e))

    return articles


@router.get("/news")
async def security_news(force: bool = Query(False)):
    """Fetch security news from RSS feeds with ISO 27001 recommendations."""
    global _news_cache, _news_cache_time

    # Return cached data if fresh (unless force refresh)
    if not force and _news_cache["articles"] and (time.time() - _news_cache_time) < _news_cache_ttl:
        return _news_cache

    all_articles = []
    source_count = 0

    async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "RiskApp/3.0 SecurityNewsFetcher"}) as client:
        for source, url in RSS_FEEDS:
            articles = await _fetch_rss_feed(client, source, url)
            if articles:
                all_articles.extend(articles)
                source_count += 1

    # Sort by source diversity then recency
    all_articles.sort(key=lambda a: a.get("published", ""), reverse=True)

    result = {
        "articles": all_articles[:30],  # Cap at 30 total
        "fetched_at": datetime.utcnow().isoformat(),
        "source_count": source_count,
    }

    _news_cache = result
    _news_cache_time = time.time()

    return result


@router.get("/summary")
async def intel_summary(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated threat intelligence summary."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    # Total counts
    total_assets = (await db.execute(select(sa_func.count(Asset.id)))).scalar() or 0
    total_findings = (await db.execute(select(sa_func.count(Finding.id)))).scalar() or 0
    total_threats = (await db.execute(select(sa_func.count(Threat.id)))).scalar() or 0
    total_risks = (await db.execute(select(sa_func.count(Risk.id)))).scalar() or 0

    # Recent threats (in period)
    recent_threats_count = (await db.execute(
        select(sa_func.count(Threat.id)).where(Threat.created_at >= cutoff)
    )).scalar() or 0

    # Threats by type
    threat_by_type_rows = (await db.execute(
        select(Threat.threat_type, sa_func.count(Threat.id))
        .where(Threat.created_at >= cutoff)
        .group_by(Threat.threat_type)
    )).all()
    threat_by_type = {row[0]: row[1] for row in threat_by_type_rows}

    # Findings by severity (in period)
    sev_rows = (await db.execute(
        select(Finding.severity, sa_func.count(Finding.id))
        .where(Finding.created_at >= cutoff)
        .group_by(Finding.severity)
    )).all()
    findings_by_severity = {row[0]: row[1] for row in sev_rows}

    # Risk distribution
    risk_rows = (await db.execute(
        select(Risk.risk_level, sa_func.count(Risk.id))
        .group_by(Risk.risk_level)
    )).all()
    risk_distribution = {row[0]: row[1] for row in risk_rows}

    # Open critical/high findings
    open_critical_high = (await db.execute(
        select(sa_func.count(Finding.id))
        .where(Finding.severity.in_(["critical", "high"]), Finding.status == "open")
    )).scalar() or 0

    # Critical risks
    critical_risks = (await db.execute(
        select(sa_func.count(Risk.id)).where(Risk.risk_level == "critical")
    )).scalar() or 0

    # Top 10 MITRE techniques
    mitre_rows = (await db.execute(
        select(MitreMapping.technique_id, MitreMapping.technique_name, MitreMapping.tactic, sa_func.count(MitreMapping.id).label("count"))
        .group_by(MitreMapping.technique_id, MitreMapping.technique_name, MitreMapping.tactic)
        .order_by(sa_func.count(MitreMapping.id).desc())
        .limit(10)
    )).all()
    top_mitre = [
        {"technique_id": r[0], "technique_name": r[1], "tactic": r[2], "count": r[3]}
        for r in mitre_rows
    ]

    # Asset exposure — top 10 assets with most threats
    exposure_rows = (await db.execute(
        select(
            Asset.id, Asset.hostname, Asset.ip_address, Asset.criticality,
            sa_func.count(Threat.id).label("threat_count"),
        )
        .join(Threat, Threat.asset_id == Asset.id)
        .group_by(Asset.id, Asset.hostname, Asset.ip_address, Asset.criticality)
        .order_by(sa_func.count(Threat.id).desc())
        .limit(10)
    )).all()
    asset_exposure = [
        {"asset_id": r[0], "hostname": r[1], "ip_address": r[2], "criticality": r[3], "threat_count": r[4]}
        for r in exposure_rows
    ]

    # Recent 20 threats
    recent_threats_result = await db.execute(
        select(Threat).order_by(Threat.created_at.desc()).limit(20)
    )
    recent_threats = [
        {
            "id": t.id, "title": t.title, "threat_type": t.threat_type,
            "confidence": t.confidence, "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in recent_threats_result.scalars().all()
    ]

    return {
        "period_days": days,
        "totals": {
            "assets": total_assets,
            "findings": total_findings,
            "threats": total_threats,
            "risks": total_risks,
        },
        "recent_threats_count": recent_threats_count,
        "threat_by_type": threat_by_type,
        "findings_by_severity": findings_by_severity,
        "risk_distribution": risk_distribution,
        "open_critical_high": open_critical_high,
        "critical_risks": critical_risks,
        "top_mitre": top_mitre,
        "asset_exposure": asset_exposure,
        "recent_threats": recent_threats,
    }


@router.get("/daily-brief")
async def daily_brief(db: AsyncSession = Depends(get_db)):
    """AI-generated or template-based daily threat brief."""
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)

    total_assets = (await db.execute(select(sa_func.count(Asset.id)))).scalar() or 0
    new_findings_24h = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.created_at >= cutoff_24h)
    )).scalar() or 0
    new_threats_24h = (await db.execute(
        select(sa_func.count(Threat.id)).where(Threat.created_at >= cutoff_24h)
    )).scalar() or 0
    open_critical = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.severity == "critical", Finding.status == "open")
    )).scalar() or 0
    open_high = (await db.execute(
        select(sa_func.count(Finding.id)).where(Finding.severity == "high", Finding.status == "open")
    )).scalar() or 0
    critical_risks = (await db.execute(
        select(sa_func.count(Risk.id)).where(Risk.risk_level == "critical")
    )).scalar() or 0

    stats_context = {
        "total_assets": total_assets,
        "new_findings_24h": new_findings_24h,
        "new_threats_24h": new_threats_24h,
        "open_critical": open_critical,
        "open_high": open_high,
        "critical_risks": critical_risks,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
    }

    # Try AI-generated brief
    ai_generated = False
    brief = ""
    if settings.ai_api_key or settings.ai_provider == "ollama":
        try:
            brief = await _generate_ai_brief(stats_context)
            ai_generated = True
        except Exception as e:
            logger.warning("AI brief generation failed, using template", error=str(e))

    if not brief:
        brief = _generate_template_brief(stats_context)

    return {
        "brief": brief,
        "ai_generated": ai_generated,
        "stats": stats_context,
    }


async def _generate_ai_brief(stats: dict) -> str:
    """Generate brief using configured AI provider."""
    prompt = (
        f"You are a cybersecurity analyst. Write a concise daily threat intelligence brief (3-5 paragraphs, markdown) "
        f"for a home network security platform.\n\n"
        f"Current stats as of {stats['date']}:\n"
        f"- Total monitored assets: {stats['total_assets']}\n"
        f"- New findings (24h): {stats['new_findings_24h']}\n"
        f"- New threats (24h): {stats['new_threats_24h']}\n"
        f"- Open critical findings: {stats['open_critical']}\n"
        f"- Open high findings: {stats['open_high']}\n"
        f"- Critical risk scenarios: {stats['critical_risks']}\n\n"
        f"Include: executive summary, key concerns, recommended actions. Be specific and actionable."
    )

    if settings.ai_provider == "ollama":
        url = f"{settings.ai_base_url}/api/generate"
        payload = {"model": settings.ai_model, "prompt": prompt, "stream": False}
    else:
        url = f"{settings.ai_base_url}/v1/chat/completions"
        payload = {
            "model": settings.ai_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }

    headers = {}
    if settings.ai_api_key:
        headers["Authorization"] = f"Bearer {settings.ai_api_key}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    if settings.ai_provider == "ollama":
        return data.get("response", "")
    else:
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")


def _generate_template_brief(stats: dict) -> str:
    """Generate a template-based brief when AI is unavailable."""
    severity_label = "stable"
    if stats["open_critical"] > 0:
        severity_label = "elevated"
    elif stats["open_high"] > 3:
        severity_label = "moderate"

    brief = f"## Daily Threat Intelligence Brief — {stats['date']}\n\n"
    brief += f"### Executive Summary\n\n"
    brief += (
        f"The network security posture is **{severity_label}**. "
        f"Currently monitoring **{stats['total_assets']}** assets. "
    )

    if stats["new_findings_24h"] > 0 or stats["new_threats_24h"] > 0:
        brief += (
            f"In the last 24 hours, **{stats['new_findings_24h']}** new findings "
            f"and **{stats['new_threats_24h']}** new threats were identified.\n\n"
        )
    else:
        brief += "No new findings or threats in the last 24 hours.\n\n"

    brief += "### Key Metrics\n\n"
    brief += f"| Metric | Count |\n|---|---|\n"
    brief += f"| Open Critical Findings | {stats['open_critical']} |\n"
    brief += f"| Open High Findings | {stats['open_high']} |\n"
    brief += f"| Critical Risk Scenarios | {stats['critical_risks']} |\n"
    brief += f"| New Findings (24h) | {stats['new_findings_24h']} |\n"
    brief += f"| New Threats (24h) | {stats['new_threats_24h']} |\n\n"

    if stats["open_critical"] > 0:
        brief += "### Recommended Actions\n\n"
        brief += f"- **Immediate**: Address {stats['open_critical']} critical finding(s) — these represent active risk to the network\n"
        brief += f"- **Short-term**: Review and triage {stats['open_high']} high-severity findings within SLA\n"
        brief += f"- **Ongoing**: Monitor {stats['critical_risks']} critical risk scenarios for changes\n"
    elif stats["open_high"] > 0:
        brief += "### Recommended Actions\n\n"
        brief += f"- Review and prioritize {stats['open_high']} open high-severity findings\n"
        brief += "- Run the AI Copilot triage for automated prioritization\n"
    else:
        brief += "### Status\n\n"
        brief += "No critical or high-severity findings require immediate attention. Continue routine monitoring.\n"

    return brief


# ─── Threat Intel Lookup Endpoints ────────────────────────────────────────────

@router.get("/cve/{cve_id}")
async def lookup_cve(cve_id: str = Path(..., description="CVE ID to look up")):
    """Aggregated CVE lookup: KEV + EPSS + cvefeed.io."""
    feed_cache = _get_feed_cache()
    await feed_cache.ensure_kev_fresh()
    await feed_cache.ensure_epss_fresh([cve_id])

    kev = feed_cache.get_kev_status(cve_id)
    epss = feed_cache.get_epss_score(cve_id)
    cve_detail = await feed_cache.lookup_cve(cve_id)

    return {
        "cve_id": cve_id.upper(),
        "kev": kev,
        "epss": epss,
        "nvd": cve_detail,
        "in_kev": kev is not None,
    }


@router.get("/ip/{ip_address}")
async def lookup_ip(ip_address: str = Path(..., description="IP address to check")):
    """IP reputation lookup via AbuseIPDB, GreyNoise, OTX."""
    client = _get_ip_reputation_client()
    return await client.check_ip(ip_address)


@router.get("/ioc/{indicator}")
async def lookup_ioc(indicator: str = Path(..., description="IoC to search")):
    """IoC lookup via URLhaus and ThreatFox."""
    client = _get_ioc_client()
    urlhaus = await client.query_urlhaus(indicator)
    threatfox = await client.query_threatfox(indicator)
    return {
        "indicator": indicator,
        "urlhaus": urlhaus,
        "threatfox": threatfox,
    }


@router.get("/certs/{domain}")
async def lookup_certs(domain: str = Path(..., description="Domain for cert transparency")):
    """Certificate transparency lookup via crt.sh."""
    client = _get_ioc_client()
    certs = await client.query_crtsh(domain)
    return {
        "domain": domain,
        "certificate_count": len(certs),
        "certificates": certs,
    }


@router.get("/feed-status")
async def feed_status():
    """Current feed status: which feeds are active, counts, last refresh."""
    feed_cache = _get_feed_cache()
    stats = feed_cache.get_feed_stats()

    # Check which API-key sources are configured
    api_sources = {
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "greynoise": bool(settings.greynoise_api_key),
        "otx": bool(settings.alienvault_otx_api_key),
    }

    return {
        **stats,
        "api_sources": api_sources,
        "free_sources": ["cisa_kev", "epss", "cvefeed", "urlhaus", "threatfox", "crtsh"],
    }
