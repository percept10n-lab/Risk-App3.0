@echo off
cd /d D:\Risk-App3.0\backend
set RISK_DATABASE_URL=sqlite+aiosqlite:///data/risk_platform.db
set RISK_DEBUG=true
set RISK_DATA_DIR=data
set RISK_CONFIG_DIR=../config
set RISK_ARTIFACTS_DIR=data/artifacts
set PYTHONPATH=D:\Risk-App3.0\backend;D:\Risk-App3.0
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
