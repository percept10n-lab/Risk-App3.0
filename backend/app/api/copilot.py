from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.services.copilot_service import CopilotService
from app.services.security_agent import SecurityAgent
from app.agents.governed_copilot import GovernedCopilot
from app.agents.llm_backend import LLMBackend, LLMMessage
from app.models.finding import Finding
from app.models.risk import Risk

import structlog

logger = structlog.get_logger()

router = APIRouter()


class ChatRequest(BaseModel):
    message: str
    conversation: list[dict] = []
    context: dict | None = None


@router.post("/chat")
async def agent_chat(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    """Chat with the governed AI copilot (LLM with rule-based fallback)."""
    try:
        copilot = GovernedCopilot(db)
        response = await copilot.chat(request.message, request.conversation)
        return response
    except Exception as e:
        logger.error("Agent chat failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@router.get("/insights")
async def copilot_insights(db: AsyncSession = Depends(get_db)):
    """Get proactive security insights."""
    try:
        from app.services.insights_service import InsightsService
        service = InsightsService(db)
        return await service.get_insights()
    except Exception as e:
        logger.error("Insights failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Insights error: {str(e)}")


@router.get("/status")
async def copilot_status(db: AsyncSession = Depends(get_db)):
    """Get LLM availability and capability reputation stats."""
    try:
        copilot = GovernedCopilot(db)
        return await copilot.get_status()
    except Exception as e:
        logger.error("Status check failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Status error: {str(e)}")


@router.post("/chat/stream")
async def agent_chat_stream(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    """Stream governed chat response via SSE with tool use."""
    import json as _json

    copilot = GovernedCopilot(db)

    async def event_generator():
        try:
            async for event in copilot.chat_stream(
                request.message, request.conversation, request.context
            ):
                yield f"data: {_json.dumps(event)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("Stream failed", error=str(e))
            yield f"data: {_json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class ExecuteToolRequest(BaseModel):
    tool: str
    args: dict = {}


@router.post("/execute-tool")
async def execute_tool(request: ExecuteToolRequest, db: AsyncSession = Depends(get_db)):
    """Execute a confirmed write tool action."""
    from app.models.audit_event import AuditEvent
    from app.models.finding import Finding
    from app.models.risk import Risk
    from sqlalchemy import select
    import uuid
    from datetime import datetime

    tool = request.tool
    args = request.args

    try:
        result = ""

        if tool == "update_finding_status":
            finding_result = await db.execute(
                select(Finding).where(Finding.id == args["finding_id"])
            )
            finding = finding_result.scalar_one_or_none()
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            old_status = finding.status
            finding.status = args["new_status"]
            finding.updated_at = datetime.utcnow()
            result = f"Finding status changed: {old_status} -> {args['new_status']}"

        elif tool == "apply_risk_treatment":
            risk_result = await db.execute(
                select(Risk).where(Risk.id == args["risk_id"])
            )
            risk = risk_result.scalar_one_or_none()
            if not risk:
                raise HTTPException(status_code=404, detail="Risk not found")
            risk.treatment = args["treatment"]
            risk.treatment_plan = args.get("rationale", "")
            risk.status = "treated"
            risk.updated_at = datetime.utcnow()
            result = f"Risk treatment applied: {args['treatment']}"

        elif tool == "trigger_vulnerability_scan":
            # Delegate to vuln scan service
            from app.services.vuln_scanner import VulnScanner
            scanner = VulnScanner(db)
            scan_result = await scanner.run_scan(asset_id=args.get("asset_id"))
            result = f"Scan complete: {scan_result.get('findings_created', 0)} findings created"

        elif tool == "run_risk_analysis":
            from app.services.risk_service import RiskService
            service = RiskService(db)
            analysis = await service.analyze(asset_id=args.get("asset_id"))
            result = f"Analysis complete: {analysis.get('risks_created', 0)} risks created"

        elif tool == "generate_report":
            from app.services.report_service import ReportService
            service = ReportService(db)
            report = await service.generate(
                report_type=args["report_type"],
                title=args.get("title"),
            )
            result = f"Report generated: {report.get('id', 'unknown')}"

        elif tool == "create_note":
            event = AuditEvent(
                id=str(uuid.uuid4()),
                event_type="note",
                entity_type=args["entity_type"],
                entity_id=args["entity_id"],
                actor="user",
                action="create_note",
                new_value={"content": args["content"]},
            )
            db.add(event)
            result = "Note created."

        elif tool == "run_threat_modeling":
            from app.services.threat_service import ThreatService
            service = ThreatService(db)
            tm_result = await service.run_full_threat_modeling(asset_ids=[args["asset_id"]] if args.get("asset_id") else None)
            await db.commit()
            result = f"Threat modeling complete: {tm_result.get('threats_created', 0)} threats created across {tm_result.get('total_assets', 0)} assets"

        elif tool == "start_assessment_pipeline":
            from app.services.nmap_service import NmapService
            import uuid as _uuid
            run_id = str(_uuid.uuid4())
            service = NmapService(db)
            pipeline_result = await service.run_full_pipeline(
                target=args["target"],
                nmap_args=args.get("nmap_args", "-sV -sC"),
                run_id=run_id,
            )
            result = (
                f"Pipeline complete (run_id: {run_id}). "
                f"Findings: {pipeline_result.get('findings_created', 0)} created. "
                f"Steps: {', '.join(pipeline_result.get('steps', {}).keys())}"
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")

        # Audit log
        audit = AuditEvent(
            id=str(uuid.uuid4()),
            event_type="tool_execution",
            entity_type="copilot",
            entity_id="execute-tool",
            actor="user",
            action=tool,
            new_value={"args": args, "result": result},
        )
        db.add(audit)
        await db.flush()

        return {"status": "completed", "result": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Tool execution failed", tool=tool, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")


@router.post("/execute-tool/stream")
async def execute_tool_stream(request: ExecuteToolRequest, db: AsyncSession = Depends(get_db)):
    """Execute a streaming tool action via SSE. Streams terminal output, then LLM analysis."""
    import json as _json
    import uuid as _uuid
    import asyncio

    from app.api.ws import manager as ws_manager
    from app.agents.tools import STREAMING_TOOL_NAMES

    tool = request.tool
    args = request.args

    if tool not in STREAMING_TOOL_NAMES:
        raise HTTPException(status_code=400, detail=f"Tool {tool} does not support streaming. Use /execute-tool instead.")

    job_id = str(_uuid.uuid4())

    async def event_generator():
        queue = ws_manager.subscribe(job_id)
        tool_result = None

        try:
            # Yield initial event
            yield f"data: {_json.dumps({'type': 'status', 'message': f'Starting {tool}...', 'job_id': job_id})}\n\n"

            # Run the tool in a background task
            tool_task = asyncio.create_task(
                _run_streaming_tool(tool, args, job_id, db)
            )

            # Read from queue until the tool task completes
            while not tool_task.done():
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=0.5)
                    # Convert WS broadcast messages to SSE terminal lines
                    line = msg.get("line", "") if isinstance(msg, dict) else str(msg)
                    if not line and isinstance(msg, dict):
                        line = msg.get("detail", _json.dumps(msg))
                    yield f"data: {_json.dumps({'type': 'terminal_line', 'line': line})}\n\n"
                except asyncio.TimeoutError:
                    continue

            # Drain any remaining messages in the queue
            while not queue.empty():
                msg = queue.get_nowait()
                line = msg.get("line", "") if isinstance(msg, dict) else str(msg)
                if not line and isinstance(msg, dict):
                    line = msg.get("detail", _json.dumps(msg))
                yield f"data: {_json.dumps({'type': 'terminal_line', 'line': line})}\n\n"

            # Get the tool result
            tool_result = tool_task.result()

            # Send result summary
            yield f"data: {_json.dumps({'type': 'result', 'data': _build_result_summary(tool, tool_result)})}\n\n"

            # Stream LLM risk analysis
            result_text = _json.dumps(_build_result_summary(tool, tool_result), default=str)
            copilot = GovernedCopilot(db)

            analysis_content = ""
            async for event in copilot.analyze_tool_result(tool, args, result_text):
                if event.get("type") == "token":
                    analysis_content += event["content"]
                    yield f"data: {_json.dumps(event)}\n\n"

            # Extract suggestions
            suggestions = copilot._extract_scan_suggestions(tool, args, result_text + "\n" + analysis_content)

            yield f"data: {_json.dumps({'type': 'done', 'suggestions': suggestions})}\n\n"

        except Exception as e:
            logger.error("Streaming tool execution failed", tool=tool, error=str(e), exc_info=True)
            yield f"data: {_json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            ws_manager.unsubscribe(job_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def _run_streaming_tool(tool: str, args: dict, job_id: str, db: AsyncSession) -> dict:
    """Run a streaming tool and return its result."""
    if tool == "run_nmap_scan":
        from app.services.nmap_service import NmapService
        service = NmapService(db)
        return await service.execute_custom_scan(
            target=args["target"],
            nmap_args=args.get("nmap_args", "-sV -sC"),
            run_id=job_id,
        )
    elif tool == "run_pentest_action":
        from app.services.pentest_service import PentestService
        from app.api.ws import manager as ws_manager
        service = PentestService(db)

        async def broadcast_callback(msg: str):
            await ws_manager.broadcast(job_id, {"type": "pentest_output", "line": msg})

        return await service.execute_action(
            action_id=args["action_id"],
            target=args["target"],
            run_id=job_id,
            params=args.get("params"),
            broadcast=broadcast_callback,
        )
    else:
        return {"status": "error", "error": f"Unknown streaming tool: {tool}"}


def _build_result_summary(tool: str, result: dict) -> dict:
    """Build a concise result summary for the frontend."""
    if result.get("status") == "error":
        return {"status": "error", "error": result.get("error", "Unknown error")}

    summary = {"status": result.get("status", "completed")}

    if tool == "run_nmap_scan":
        summary["target"] = result.get("target", "")
        summary["command_line"] = result.get("command_line", "")
        summary["findings_created"] = result.get("findings_created", 0)
        summary["total_findings"] = result.get("total_findings", 0)
        hosts = result.get("scan_result", {}).get("hosts", {})
        summary["hosts_discovered"] = len(hosts)
        summary["import_result"] = result.get("import_result", {})
    elif tool == "run_pentest_action":
        summary["action"] = result.get("action", "")
        summary["target"] = result.get("target", "")
        summary["findings_created"] = result.get("findings_created", 0)
        summary["total_findings"] = result.get("total_findings", 0)

    return summary


class TriageRequest(BaseModel):
    finding_ids: list[str] = []


class RemediationRequest(BaseModel):
    finding_id: str
    context: dict = {}


class NarrativeRequest(BaseModel):
    run_id: str | None = None
    scope: str = "summary"


class InvestigateRequest(BaseModel):
    finding_id: str


class ExecuteRemediationRequest(BaseModel):
    finding_id: str
    action: str = "set_in_progress"
    params: dict = {}


class VerifyRequest(BaseModel):
    finding_id: str
    action_id: str = "port_verify"
    target: str | None = None


@router.post("/triage")
async def triage_findings(request: TriageRequest, db: AsyncSession = Depends(get_db)):
    """AI-assisted triage of findings by priority."""
    try:
        service = CopilotService(db)
        return await service.triage_findings(
            finding_ids=request.finding_ids if request.finding_ids else None
        )
    except Exception as e:
        logger.error("Triage endpoint failed", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")


@router.post("/remediation")
async def suggest_remediation(request: RemediationRequest, db: AsyncSession = Depends(get_db)):
    """Generate remediation plan for a finding."""
    service = CopilotService(db)
    result = await service.suggest_remediation(
        finding_id=request.finding_id,
        context=request.context,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/mitre-suggest")
async def suggest_mitre(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Suggest MITRE ATT&CK mappings for a finding."""
    service = CopilotService(db)
    result = await service.suggest_mitre_mappings(finding_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/narrative")
async def generate_narrative(request: NarrativeRequest, db: AsyncSession = Depends(get_db)):
    """Generate narrative summary of assessment results."""
    service = CopilotService(db)
    return await service.generate_narrative(
        run_id=request.run_id,
        scope=request.scope,
    )


@router.get("/suggestions")
async def list_suggestions(db: AsyncSession = Depends(get_db)):
    """List all AI-generated suggestions."""
    service = CopilotService(db)
    return await service.get_all_suggestions()


@router.post("/investigate")
async def investigate_finding(request: InvestigateRequest, db: AsyncSession = Depends(get_db)):
    """Step 1: Investigate a finding — gather full context, analysis, and remediation plan."""
    service = CopilotService(db)
    result = await service.investigate(request.finding_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["error"])
    return result


class GatherRequest(BaseModel):
    finding_id: str


@router.post("/gather")
async def gather_updates(request: GatherRequest, db: AsyncSession = Depends(get_db)):
    """Step 3.1: Gather patches, updates, and check admin requirements."""
    service = CopilotService(db)
    result = await service.gather(request.finding_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/execute-remediation")
async def execute_remediation(request: ExecuteRemediationRequest, db: AsyncSession = Depends(get_db)):
    """Step 4: Execute remediation action (status update, audit log)."""
    service = CopilotService(db)
    result = await service.execute_remediation(
        finding_id=request.finding_id,
        action=request.action,
        params=request.params,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/verify")
async def verify_fix(request: VerifyRequest, db: AsyncSession = Depends(get_db)):
    """Step 5: Verify fix by running a pentest action and checking results."""
    service = CopilotService(db)
    result = await service.verify_fix(
        finding_id=request.finding_id,
        action_id=request.action_id,
        target=request.target,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["error"])
    return result
