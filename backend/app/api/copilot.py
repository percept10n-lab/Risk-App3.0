from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.database import get_db
from app.services.copilot_service import CopilotService
from app.services.security_agent import SecurityAgent
from app.agents.governed_copilot import GovernedCopilot
from app.agents.llm_backend import LLMBackend, LLMMessage

import structlog

logger = structlog.get_logger()

router = APIRouter()


class ChatRequest(BaseModel):
    message: str
    conversation: list[dict] = []


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
    """Stream chat response via SSE."""
    llm = LLMBackend()
    if not await llm.is_available():
        raise HTTPException(status_code=503, detail="LLM not available")

    from app.agents.contracts import CHAT_CONTRACT

    messages = [CHAT_CONTRACT.to_system_message()]
    for turn in request.conversation[-10:]:
        messages.append(LLMMessage(role=turn.get("role", "user"), content=turn.get("content", "")))
    messages.append(LLMMessage(role="user", content=request.message))

    async def event_generator():
        try:
            async for chunk in llm.stream(messages):
                yield f"data: {chunk}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("Stream failed", error=str(e))
            yield f"data: Error: {e}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


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
