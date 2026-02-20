# Home Network Threat & Risk Platform

A comprehensive, locally-operated security platform for home network assessment,
threat modeling, and risk management.

## Features
- **Asset Discovery**: Automated network scanning and device identification
- **Vulnerability Scanning**: Security configuration checks (HTTP, TLS, SSH, DNS)
- **Threat Modeling**: C4-decomposed, STRIDE-based threat identification with live transparency — System Context (trust boundaries), Container (zones), and Component (assets) analysis with real-time console broadcast
- **Risk Assessment**: ISO 27005-compliant risk analysis with configurable matrix and IP reputation enrichment
- **MITRE ATT&CK**: Automatic technique mapping with Navigator export
- **Threat Intelligence**: Live feeds from CISA KEV, FIRST EPSS, cvefeed.io, abuse.ch (URLhaus/ThreatFox), crt.sh, AbuseIPDB, GreyNoise, and AlienVault OTX — with offline fallback
- **Evidence Chain**: SHA-256 hash chain for tamper-evident audit trail
- **AI Copilot**: Optional AI-assisted triage and remediation suggestions
- **Reporting**: HTML/PDF reports with full evidence packages

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 20+ (for local frontend development)
- Python 3.12+ (for local backend development)

### Using Docker Compose
```bash
docker-compose up --build
```
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Local Development

**Backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## Configuration
Configuration files are in `config/`:
- `default_policy.yaml` - Scanning policy (scope, rate limits)
- `risk_matrix.yaml` - Risk assessment matrix
- `zone_model.yaml` - Network zone definitions
- `mapping_rules.yaml` - MITRE ATT&CK mapping rules
- `baselines.yaml` - Expected baseline configurations

Environment variables for threat intelligence (optional):
- `RISK_ABUSEIPDB_API_KEY` - AbuseIPDB API key
- `RISK_GREYNOISE_API_KEY` - GreyNoise Community API key
- `RISK_ALIENVAULT_OTX_API_KEY` - AlienVault OTX API key
- `RISK_THREAT_FEED_MODE` - Feed mode: `live`, `offline`, or `fallback` (default)
- `RISK_THREAT_FEED_CACHE_TTL` - Cache TTL in seconds (default: 3600)

## Project Structure
```
├── frontend/          # React + TypeScript (Vite)
├── backend/           # FastAPI + SQLAlchemy
├── mcp_servers/       # MCP tool servers
├── config/            # YAML configuration
├── data/              # SQLite DB + artifacts
├── docs/              # Documentation
└── docker-compose.yml
```

## Tech Stack
| Component | Technology |
|-----------|-----------|
| Frontend | React, TypeScript, Vite, Tailwind CSS, Zustand |
| Backend | FastAPI, SQLAlchemy 2.0, Pydantic |
| Database | SQLite (aiosqlite) |
| Scanning | python-nmap, scapy, paramiko |
| Threat Intel | httpx (CISA KEV, FIRST EPSS, cvefeed.io, abuse.ch, crt.sh, AbuseIPDB, GreyNoise, OTX) |
| Reports | Jinja2, WeasyPrint |
| MCP | Model Context Protocol (stdio transport) |

## License
Private - All rights reserved.
