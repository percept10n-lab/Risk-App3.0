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

    async def chat_stream(
        self, message: str, conversation: list[dict] | None = None, context: dict | None = None
    ):
        """Async generator — governed streaming chat. Yields SSE event dicts."""
        conversation = conversation or []

        # 1. Check if LLM is available
        llm_available = await self.llm.is_available()
        if not llm_available:
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            yield {"type": "token", "content": result.get("content", "")}
            yield {"type": "done", "source": "rule_based", "suggestions": []}
            return

        # 2. Check reputation
        if not await self.reputation.is_allowed("chat"):
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            yield {"type": "token", "content": result.get("content", "")}
            yield {"type": "done", "source": "rule_based", "suggestions": []}
            return

        # 3. Explicit commands stay rule-based
        if self._is_explicit_command(message):
            result = await self.fallback_agent.chat(message, conversation)
            result["source"] = "rule_based"
            yield {"type": "token", "content": result.get("content", "")}
            yield {"type": "done", "source": "rule_based", "suggestions": []}
            return

        # 4. Build LLM messages
        try:
            messages = self._build_messages(CHAT_CONTRACT, message, conversation, context)

            # 5. Stream with tools
            collected_content = ""
            async for event in self.llm.stream_with_tools(
                messages=messages,
                tools=COPILOT_TOOLS,
                tool_executor=self.tool_executor.execute,
            ):
                if event["type"] == "token":
                    collected_content += event["content"]
                yield event

            # 6. Verify output
            if collected_content.strip():
                verification = await self.verifier.verify(collected_content, "chat")

                if verification.score >= 0.5:
                    outcome_score = 1.0 if verification.passed and verification.score >= 0.75 else 0.5
                else:
                    outcome_score = -1.0

                await self.reputation.record_outcome("chat", outcome_score)

                # Extract suggestions
                suggestions = self._extract_suggestions(collected_content, message)

                yield {
                    "type": "done",
                    "source": "llm",
                    "model": self.llm.model,
                    "suggestions": suggestions,
                    "verification": {
                        "passed": verification.passed,
                        "score": verification.score,
                    },
                }
            else:
                yield {"type": "done", "source": "llm", "suggestions": []}

        except Exception as e:
            logger.error("Streaming chat failed, falling back", error=str(e), exc_info=True)
            result = await self.fallback_agent.chat(message, conversation)
            yield {"type": "token", "content": result.get("content", "")}
            yield {"type": "done", "source": "rule_based", "suggestions": []}

    async def analyze_tool_result(
        self, tool_name: str, args: dict, result_summary: str
    ):
        """Async generator — analyze tool execution results from a risk perspective.
        Yields SSE event dicts with type 'token' for streaming analysis text.
        Falls back to rule-based suggestions if LLM unavailable.
        """
        target = args.get("target", args.get("action_id", ""))

        # Try LLM analysis
        llm_available = await self.llm.is_available()
        if llm_available and await self.reputation.is_allowed("chat"):
            try:
                messages = [
                    CHAT_CONTRACT.to_system_message(),
                    LLMMessage(
                        role="user",
                        content=(
                            f"I just ran **{tool_name}** on `{target}`. Here are the results:\n\n"
                            f"```\n{result_summary[:3000]}\n```\n\n"
                            "Analyze these results from a **risk perspective**. "
                            "Identify the most important security concerns, explain their impact, "
                            "and suggest concrete next actions I should take. "
                            "Do NOT call any tools — just provide your written analysis."
                        ),
                    ),
                ]

                async for event in self.llm.stream_with_tools(
                    messages=messages,
                    tools=[],
                    tool_executor=self.tool_executor.execute,
                ):
                    if event["type"] == "token":
                        yield event

                return
            except Exception as e:
                logger.error("LLM analysis failed, using rule-based", error=str(e))

        # Rule-based fallback analysis
        fallback = self._rule_based_analysis(tool_name, args, result_summary)
        yield {"type": "token", "content": fallback}

    @staticmethod
    def _rule_based_analysis(tool_name: str, args: dict, result_summary: str) -> str:
        """Generate rule-based analysis when LLM is unavailable."""
        lines = []
        summary_lower = result_summary.lower()

        if tool_name == "run_nmap_scan":
            lines.append("## Scan Analysis\n")
            if "open" in summary_lower:
                lines.append("Open ports were detected. Review each service for:")
                lines.append("- Unnecessary exposure (close unused ports)")
                lines.append("- Missing encryption (replace Telnet/FTP with SSH/SFTP)")
                lines.append("- Default credentials on admin interfaces")
            if "high" in summary_lower or "critical" in summary_lower:
                lines.append("\n**High-risk services detected.** Prioritize these for immediate remediation.")
            else:
                lines.append("\nNo critical exposures found in this scan.")
        elif tool_name == "run_pentest_action":
            lines.append("## Security Test Results\n")
            if "finding" in summary_lower:
                lines.append("Findings were generated. Review severity levels and apply fixes.")
            else:
                lines.append("Test completed with no significant findings.")
        else:
            lines.append("## Results Summary\n")
            lines.append("Tool execution completed. Review the output above for details.")

        return "\n".join(lines)

    @staticmethod
    def _extract_scan_suggestions(tool_name: str, args: dict, result_summary: str) -> list[str]:
        """Extract follow-up suggestions specific to scan/tool results."""
        suggestions = []
        summary_lower = result_summary.lower()
        target = args.get("target", "")

        if tool_name == "run_nmap_scan":
            if "open" in summary_lower and ("80" in summary_lower or "443" in summary_lower or "http" in summary_lower):
                suggestions.append(f"Run pentest http_headers on {target}")
            if "open" in summary_lower and ("443" in summary_lower or "tls" in summary_lower or "ssl" in summary_lower):
                suggestions.append(f"Run pentest tls_check on {target}")
            if "open" in summary_lower and ("22" in summary_lower or "ssh" in summary_lower):
                suggestions.append(f"Run pentest ssh_hardening on {target}")
            if "open" in summary_lower:
                suggestions.append("Run threat modeling")
                suggestions.append(f"Run pentest web_vuln_probe on {target}")
        elif tool_name == "run_pentest_action":
            action_id = args.get("action_id", "")
            if "finding" in summary_lower or "vuln" in summary_lower:
                suggestions.append("Generate security report")
            if action_id == "http_headers":
                suggestions.append(f"Run pentest tls_check on {target}")
                suggestions.append(f"Run pentest web_vuln_probe on {target}")
            if action_id == "tls_check":
                suggestions.append(f"Run pentest web_vuln_probe on {target}")
            if action_id == "ssh_hardening":
                suggestions.append(f"Run pentest default_creds on {target}")
            suggestions.append("Run threat modeling")
        elif tool_name == "run_threat_modeling":
            suggestions.append("View MITRE ATT&CK mappings")
            suggestions.append("Run risk analysis")
            suggestions.append("Generate threat report")
        elif tool_name == "start_assessment_pipeline":
            suggestions.append("Show security posture")
            suggestions.append("Show critical findings")
            suggestions.append("Generate executive report")

        return suggestions[:4]

    @staticmethod
    def _extract_suggestions(content: str, user_message: str) -> list[str]:
        """Extract follow-up suggestions based on response content."""
        suggestions = []
        content_lower = content.lower()

        if "finding" in content_lower or "vulnerability" in content_lower:
            suggestions.append("Show remediation steps")
            suggestions.append("Which findings are most urgent?")
        if "risk" in content_lower:
            suggestions.append("How can I reduce these risks?")
            suggestions.append("Show the risk matrix")
        if "threat" in content_lower:
            suggestions.append("Show MITRE ATT&CK mappings")
            suggestions.append("Which threats are highest confidence?")
        if "asset" in content_lower:
            suggestions.append("Scan for new vulnerabilities")
            suggestions.append("Show asset exposure details")
        if "critical" in content_lower or "high" in content_lower:
            suggestions.append("Generate a report")
            suggestions.append("Start remediation workflow")
        # Scan-specific suggestions
        if "nmap" in content_lower or "scan" in content_lower:
            suggestions.append("Run security tests on discovered hosts")
        if "open port" in content_lower:
            suggestions.append("Check HTTP headers on exposed services")

        # Keep max 4 unique suggestions
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:4]

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
        context: dict | None = None,
    ) -> list[LLMMessage]:
        """Build message list: system + context + last 10 turns + user message."""
        messages = [contract.to_system_message()]

        # Inject page context if provided
        if context:
            ctx_parts = []
            if context.get("page"):
                ctx_parts.append(f"The user is currently on the {context['page']} page.")
            if context.get("entity_type") and context.get("entity_id"):
                ctx_parts.append(f"They are viewing {context['entity_type']} ID: {context['entity_id']}.")
            if context.get("filters"):
                ctx_parts.append(f"Active filters: {context['filters']}.")
            if context.get("summary"):
                ctx_parts.append(context["summary"])
            if ctx_parts:
                messages.append(LLMMessage(
                    role="system",
                    content="Current user context: " + " ".join(ctx_parts),
                ))

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
