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
