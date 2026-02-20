"""
GovernedCopilot — Main orchestrator wrapping LLM, tools, verifier, reputation, and rule-based fallback.
"""

import re
import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm_backend import LLMBackend, LLMMessage
from app.agents.tools import COPILOT_TOOLS, ToolExecutor
from app.agents.contracts import (
    CHAT_CONTRACT,
    TRIAGE_CONTRACT,
    REMEDIATION_CONTRACT,
    NARRATIVE_CONTRACT,
)
from app.agents.verifier import OutputVerifier
from app.agents.reputation import ReputationTracker
from app.services.security_agent import SecurityAgent
from app.models.audit_event import AuditEvent

import structlog

logger = structlog.get_logger()

# Commands that must stay deterministic (rule-based)
EXPLICIT_COMMANDS = re.compile(
    r'\b(mark|execute|apply|set_fixed|set_in_progress|set_accepted|run remediation)\b',
    re.IGNORECASE,
)


class GovernedCopilot:
    """Hybrid copilot: LLM intelligence with rule-based fallback and verification."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.llm = LLMBackend()
        self.tool_executor = ToolExecutor(db)
        self.verifier = OutputVerifier(db)
        self.reputation = ReputationTracker(db)
        self.fallback_agent = SecurityAgent(db)

    async def chat(self, message: str, conversation: list[dict] | None = None) -> dict:
        """Process a user message — routes to LLM or rule-based fallback."""
        conversation = conversation or []

        # 1. Check if LLM is available
        llm_available = await self.llm.is_available()
        if not llm_available:
            logger.info("LLM unavailable, using rule-based fallback")
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            result["source_detail"] = "LLM unavailable"
            return result

        # 2. Check reputation
        if not await self.reputation.is_allowed("chat"):
            logger.warning("Chat capability quarantined, using fallback")
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            result["source_detail"] = "Capability quarantined"
            return result

        # 3. Explicit commands stay rule-based for determinism
        if self._is_explicit_command(message):
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            result["source_detail"] = "Deterministic command"
            return result

        # 4. Build LLM messages
        try:
            messages = self._build_messages(CHAT_CONTRACT, message, conversation)

            # 5. Complete with tool use
            response = await self.llm.complete_with_tools(
                messages=messages,
                tools=COPILOT_TOOLS,
                tool_executor=self.tool_executor.execute,
            )

            content = response.content or ""
            if not content.strip():
                # Empty response — fall back
                result = await self.fallback_agent.chat(message, conversation)
                result["source"] = "rule_based"
                result["source_detail"] = "Empty LLM response"
                return result

            # 6. Verify output
            verification = await self.verifier.verify(content, "chat")

            # 7. Score the outcome
            if verification.passed and verification.score >= 0.75:
                outcome_score = 1.0
            elif verification.score >= 0.5:
                outcome_score = 0.5
            else:
                outcome_score = -1.0

            # Update reputation
            new_rep = await self.reputation.record_outcome(
                "chat",
                outcome_score,
                {
                    "gates": [{"name": g.name, "passed": g.passed, "detail": g.detail} for g in verification.gates],
                    "score": verification.score,
                },
            )

            # 8. If verification fails hard, fall back
            if verification.score < 0.5:
                logger.warning(
                    "Verification failed, falling back to rule-based",
                    score=verification.score,
                    flagged=verification.flagged_claims,
                )
                result = await self.fallback_agent.chat(message, conversation)
                result["source"] = "rule_based"
                result["source_detail"] = "Verification failed"
                result["verification"] = {
                    "passed": False,
                    "score": verification.score,
                    "warnings": verification.flagged_claims,
                }
                return result

            # 9. Log to audit trail
            await self._log_audit(
                action="llm_chat",
                detail={
                    "model": response.model,
                    "usage": response.usage,
                    "verification_score": verification.score,
                    "reputation": new_rep,
                },
            )

            # 10. Return LLM response
            result = {
                "role": "assistant",
                "content": content,
                "timestamp": datetime.utcnow().isoformat(),
                "actions": [],
                "source": "llm",
                "model": response.model,
                "verification": {
                    "passed": verification.passed,
                    "score": verification.score,
                    "warnings": verification.warnings,
                },
            }

            return result

        except Exception as e:
            logger.error("LLM chat failed, falling back", error=str(e), exc_info=True)
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            result["source_detail"] = f"LLM error: {type(e).__name__}"
            return result

    async def generate_triage_rationale(self, triage_results: dict) -> dict:
        """Add LLM prose to deterministic triage scores."""
        if not await self.llm.is_available() or not await self.reputation.is_allowed("triage"):
            return triage_results

        try:
            findings_text = ""
            for f in triage_results.get("findings", [])[:10]:
                findings_text += (
                    f"- {f['severity'].upper()} | Score: {f.get('priority_score', 0)} | "
                    f"{f['title']} | {f['category']}\n"
                )

            messages = [
                TRIAGE_CONTRACT.to_system_message(),
                LLMMessage(
                    role="user",
                    content=f"Explain the priority ordering of these triaged findings:\n\n{findings_text}",
                ),
            ]

            response = await self.llm.complete_with_tools(
                messages=messages,
                tools=COPILOT_TOOLS,
                tool_executor=self.tool_executor.execute,
            )

            if response.content:
                verification = await self.verifier.verify(response.content, "triage")
                await self.reputation.record_outcome(
                    "triage",
                    1.0 if verification.passed else 0.5 if verification.score >= 0.5 else -1.0,
                )
                if verification.score >= 0.5:
                    triage_results["llm_rationale"] = response.content
                    triage_results["rationale_source"] = "llm"

        except Exception as e:
            logger.error("Triage rationale generation failed", error=str(e))

        return triage_results

    async def generate_remediation_plan(self, finding_id: str, rule_based_plan: dict) -> dict:
        """Enhance rule-based remediation plan with LLM detail."""
        if not await self.llm.is_available() or not await self.reputation.is_allowed("remediation"):
            return rule_based_plan

        try:
            plan_text = ""
            for step in rule_based_plan.get("plan", {}).get("steps", []):
                plan_text += f"{step.get('step', '')}. {step.get('action', '')} — {step.get('detail', '')}\n"

            messages = [
                REMEDIATION_CONTRACT.to_system_message(),
                LLMMessage(
                    role="user",
                    content=(
                        f"Enhance this remediation plan for finding {finding_id}:\n\n"
                        f"Title: {rule_based_plan.get('title', 'Unknown')}\n"
                        f"Severity: {rule_based_plan.get('severity', 'unknown')}\n\n"
                        f"Current plan:\n{plan_text}\n\n"
                        "Add specific commands, prerequisites, rollback steps, and verification."
                    ),
                ),
            ]

            response = await self.llm.complete_with_tools(
                messages=messages,
                tools=COPILOT_TOOLS,
                tool_executor=self.tool_executor.execute,
            )

            if response.content:
                verification = await self.verifier.verify(response.content, "remediation")
                await self.reputation.record_outcome(
                    "remediation",
                    1.0 if verification.passed else 0.5 if verification.score >= 0.5 else -1.0,
                )
                if verification.score >= 0.5:
                    rule_based_plan["llm_enhanced_plan"] = response.content
                    rule_based_plan["plan_source"] = "llm_enhanced"

        except Exception as e:
            logger.error("Remediation plan enhancement failed", error=str(e))

        return rule_based_plan

    async def generate_narrative(self, report_data: dict) -> dict:
        """Generate executive summary narrative."""
        if not await self.llm.is_available() or not await self.reputation.is_allowed("narrative"):
            return {"narrative": None, "source": "unavailable"}

        try:
            messages = [
                NARRATIVE_CONTRACT.to_system_message(),
                LLMMessage(
                    role="user",
                    content=(
                        "Write an executive summary based on this security assessment data. "
                        "Use the tools to get current statistics."
                    ),
                ),
            ]

            response = await self.llm.complete_with_tools(
                messages=messages,
                tools=COPILOT_TOOLS,
                tool_executor=self.tool_executor.execute,
            )

            if response.content:
                verification = await self.verifier.verify(response.content, "narrative")
                await self.reputation.record_outcome(
                    "narrative",
                    1.0 if verification.passed else 0.5 if verification.score >= 0.5 else -1.0,
                )
                if verification.score >= 0.5:
                    return {
                        "narrative": response.content,
                        "source": "llm",
                        "model": response.model,
                        "verification": {
                            "passed": verification.passed,
                            "score": verification.score,
                        },
                    }

        except Exception as e:
            logger.error("Narrative generation failed", error=str(e))

        return {"narrative": None, "source": "unavailable"}

    async def get_status(self) -> dict:
        """LLM availability + reputation stats (for frontend dashboard)."""
        available = await self.llm.is_available(force_check=True)
        reputation_stats = await self.reputation.get_all_stats()

        return {
            "llm_available": available,
            "provider": self.llm.provider,
            "model": self.llm.model,
            "base_url": self.llm.base_url,
            "reputation": reputation_stats,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_explicit_command(message: str) -> bool:
        """Check if message contains explicit action commands."""
        return bool(EXPLICIT_COMMANDS.search(message))

    @staticmethod
    def _build_messages(
        contract,
        user_message: str,
        conversation: list[dict],
    ) -> list[LLMMessage]:
        """Build message list: system + last 10 turns + user message."""
        messages = [contract.to_system_message()]

        # Include last 10 conversation turns
        recent = conversation[-10:] if len(conversation) > 10 else conversation
        for turn in recent:
            messages.append(LLMMessage(
                role=turn.get("role", "user"),
                content=turn.get("content", ""),
            ))

        messages.append(LLMMessage(role="user", content=user_message))
        return messages

    async def _log_audit(self, action: str, detail: dict) -> None:
        """Log LLM interaction to audit trail."""
        event = AuditEvent(
            id=str(uuid.uuid4()),
            event_type="llm_interaction",
            entity_type="copilot",
            entity_id="governed_copilot",
            actor="governed_copilot",
            action=action,
            new_value=detail,
        )
        self.db.add(event)
