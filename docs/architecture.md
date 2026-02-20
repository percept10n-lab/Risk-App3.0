# Home Network Threat & Risk Platform - Architecture

## Overview
A locally-operated web application for home network security assessment,
threat modeling, and risk management. Built on ISO 27005 principles with
evidence-first, defensive-only approach.

## Architecture
- **Frontend**: React + TypeScript (Vite) with Tailwind CSS
- **Backend**: Python FastAPI with async SQLAlchemy
- **Database**: SQLite (via aiosqlite)
- **MCP Servers**: Specialized tools running as subprocesses
- **Orchestration**: Router Agent (state machine) with Policy Engine

## Key Principles
1. **Evidence-first**: Every finding backed by artifacts with SHA-256 hash chain
2. **Defensive-only**: No offensive capabilities, policy-gated actions
3. **ISO 27005 compliant**: Full risk lifecycle (identify → analyze → evaluate → treat)
4. **Auditable**: Append-only audit trail for all decisions and overrides
5. **MCP-orchestrated**: Modular tool servers via Model Context Protocol
6. **C4-decomposed threat modeling**: System Context → Container → Component analysis with STRIDE
7. **Live threat intelligence**: Resilient 3-mode (live/offline/fallback) feeds from CISA KEV, FIRST EPSS, cvefeed.io, abuse.ch, and optional API-key sources

## Threat Modeling Architecture (C4 + STRIDE)

The threat modeling engine performs a three-level decomposition based on the C4 model:

```
┌──────────────────────────────────────────────┐
│  C4 Level 1: System Context                  │
│  Trust boundary analysis                     │
│  WAN↔LAN, LAN↔IoT, LAN↔Guest, WAN↔DMZ      │
├──────────────────────────────────────────────┤
│  C4 Level 2: Container                       │
│  Per-zone STRIDE analysis                    │
│  Groups assets by zone, evaluates zone-level │
│  threats with STRIDE breakdown               │
├──────────────────────────────────────────────┤
│  C4 Level 3: Component                       │
│  Per-asset STRIDE analysis                   │
│  Individual device threats based on services, │
│  exposure profile, and asset type            │
└──────────────────────────────────────────────┘
```

Each threat is tagged with:
- `c4_level`: `system_context`, `container`, or `component`
- `stride_category_detail`: Human-readable explanation of why the STRIDE category applies

Progress is broadcast in real-time to the frontend via WebSocket `step_detail` messages.

## External Threat Intelligence Architecture

```
┌─────────────────────────────────────────────────┐
│              ThreatFeedCache                     │
│  Mode: live | offline | fallback                 │
├─────────────────────────────────────────────────┤
│  Free sources (no API key):                      │
│  ├─ CISA KEV (JSON catalog, cached 24h)          │
│  ├─ FIRST EPSS (batch API, cached 24h per CVE)   │
│  ├─ cvefeed.io (CVE detail + CVSS, cached)         │
│  ├─ abuse.ch URLhaus (POST API)                  │
│  ├─ abuse.ch ThreatFox (POST API)               │
│  └─ crt.sh (certificate transparency, GET API)   │
├─────────────────────────────────────────────────┤
│  API-key sources (optional):                     │
│  ├─ AbuseIPDB (IP reputation)                    │
│  ├─ GreyNoise (internet noise classification)    │
│  └─ AlienVault OTX (threat pulse intelligence)   │
└─────────────────────────────────────────────────┘
```

### Feed Modes
- **live**: Always fetch from external APIs (requires internet)
- **offline**: Use built-in static data only (no network calls)
- **fallback** (default): Try live first, fall back to static data on failure

### Integration Points
- **Exploit Enrichment**: KEV/EPSS data enhances exploitability scoring during pipeline Step 5
- **Risk Analysis**: IP reputation data contributes to likelihood calculation in pipeline Step 7
- **Finding Detail**: CVE-linked findings display live KEV/EPSS/cvefeed.io data
- **Intel Page**: Interactive lookup tools for CVE, IP, IoC, and certificate queries

### API Endpoints
| Endpoint | Source | Auth |
|----------|--------|------|
| `GET /intel/cve/{cve_id}` | KEV + EPSS + cvefeed.io | None |
| `GET /intel/ip/{ip}` | AbuseIPDB + GreyNoise + OTX | API keys |
| `GET /intel/ioc/{indicator}` | URLhaus + ThreatFox | None |
| `GET /intel/certs/{domain}` | crt.sh | None |
| `GET /intel/feed-status` | All feeds | None |
