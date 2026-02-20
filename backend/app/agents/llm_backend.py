"""
Unified LLM Adapter — Ollama native + OpenAI-compatible APIs.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Awaitable

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


@dataclass
class LLMMessage:
    role: str
    content: str
    tool_calls: list[dict] | None = None
    name: str | None = None


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict] | None = None
    model: str = ""
    usage: dict = field(default_factory=dict)
    finish_reason: str = ""


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict


class LLMBackend:
    """Async interface to Ollama native and OpenAI-compatible APIs."""

    def __init__(
        self,
        provider: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
    ):
        self.provider = provider or settings.ai_provider
        self.base_url = (base_url or settings.ai_base_url).rstrip("/")
        self.model = model or settings.ai_model
        self.api_key = api_key or settings.ai_api_key
        self.timeout = timeout or getattr(settings, "ai_timeout", 120.0)

        self._available: bool | None = None
        self._available_checked_at: float = 0
        self._cache_ttl = 30  # seconds

    @property
    def is_ollama(self) -> bool:
        return self.provider == "ollama"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def is_available(self, force_check: bool = False) -> bool:
        """Check if the LLM backend is reachable. Caches result."""
        now = time.monotonic()
        if not force_check and self._available is not None and (now - self._available_checked_at) < self._cache_ttl:
            return self._available

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                if self.is_ollama:
                    resp = await client.get(f"{self.base_url}/api/tags")
                else:
                    resp = await client.get(
                        f"{self.base_url}/v1/models",
                        headers=self._headers(),
                    )
                self._available = resp.status_code == 200
        except Exception:
            self._available = False

        self._available_checked_at = now
        return self._available

    async def complete(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.3,
    ) -> LLMResponse:
        """Single completion — routes to Ollama native or OpenAI-compat."""
        if self.is_ollama:
            return await self._complete_ollama_native(messages, tools, temperature)
        return await self._complete_openai_compat(messages, tools, temperature)

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition],
        tool_executor: Callable[[str, dict], Awaitable[str]],
        max_iterations: int | None = None,
    ) -> LLMResponse:
        """Agentic tool-use loop: complete → tool_calls → execute → repeat."""
        if max_iterations is None:
            max_iterations = getattr(settings, "ai_max_tool_iterations", 5)

        working_messages = list(messages)

        for _ in range(max_iterations):
            response = await self.complete(working_messages, tools)

            if not response.tool_calls:
                return response

            # Append assistant message with tool calls
            working_messages.append(LLMMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=response.tool_calls,
            ))

            # Execute each tool call
            for tc in response.tool_calls:
                func = tc.get("function", tc)
                name = func.get("name", "")
                args = func.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}

                try:
                    result = await tool_executor(name, args)
                except Exception as e:
                    result = f"Error executing {name}: {e}"

                # Append tool result
                if self.is_ollama:
                    working_messages.append(LLMMessage(
                        role="tool",
                        content=str(result),
                        name=name,
                    ))
                else:
                    working_messages.append(LLMMessage(
                        role="tool",
                        content=str(result),
                        name=tc.get("id", name),
                    ))

        # Max iterations reached — return last response
        return await self.complete(working_messages)

    async def stream_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition],
        tool_executor: Callable[[str, dict], Awaitable[str]],
        max_iterations: int | None = None,
    ) -> AsyncIterator[dict]:
        """Agentic tool loop with streaming final answer.

        Yields SSE-style dicts:
          {"type": "status", "message": "..."}
          {"type": "tool_result", "tool": "...", "summary": "..."}
          {"type": "token", "content": "..."}
        """
        if max_iterations is None:
            max_iterations = getattr(settings, "ai_max_tool_iterations", 5)

        working_messages = list(messages)

        for _ in range(max_iterations):
            # Non-streaming complete for tool iterations
            response = await self.complete(working_messages, tools)

            if not response.tool_calls:
                # No tool calls → stream the final answer
                # Re-do as streaming for token-by-token output
                # But we already have the content from complete(), so yield it in chunks
                content = response.content or ""
                if content:
                    # Yield as tokens (split by spaces to simulate streaming)
                    words = content.split(" ")
                    for i, word in enumerate(words):
                        token = word if i == 0 else " " + word
                        yield {"type": "token", "content": token}
                return

            # Append assistant message with tool calls
            working_messages.append(LLMMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=response.tool_calls,
            ))

            # Execute each tool call
            for tc in response.tool_calls:
                func = tc.get("function", tc)
                name = func.get("name", "")
                args = func.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}

                yield {"type": "status", "message": f"Calling {name}..."}

                try:
                    result = await tool_executor(name, args)
                except Exception as e:
                    result = f"Error executing {name}: {e}"

                # Check for pending confirmation (write tools)
                try:
                    parsed = json.loads(result) if isinstance(result, str) else result
                    if isinstance(parsed, dict) and parsed.get("pending_confirmation"):
                        yield {
                            "type": "pending_action",
                            "action": {
                                "tool": parsed.get("tool", name),
                                "args": parsed.get("args", args),
                                "description": parsed.get("description", f"Execute {name}"),
                            },
                        }
                        # Tell the LLM the action requires user approval
                        tool_msg = f"Action '{name}' requires user confirmation. I've asked the user to approve it."
                        if self.is_ollama:
                            working_messages.append(LLMMessage(role="tool", content=tool_msg, name=name))
                        else:
                            working_messages.append(LLMMessage(role="tool", content=tool_msg, name=tc.get("id", name)))
                        continue

                    if isinstance(parsed, list):
                        summary = f"Found {len(parsed)} results"
                    elif isinstance(parsed, dict) and "error" in parsed:
                        summary = parsed["error"]
                    elif isinstance(parsed, dict):
                        summary = f"Got data ({len(parsed)} fields)"
                    else:
                        summary = str(result)[:100]
                except Exception:
                    summary = str(result)[:100]

                yield {"type": "tool_result", "tool": name, "summary": summary}

                # Append tool result
                if self.is_ollama:
                    working_messages.append(LLMMessage(
                        role="tool", content=str(result), name=name,
                    ))
                else:
                    working_messages.append(LLMMessage(
                        role="tool", content=str(result), name=tc.get("id", name),
                    ))

        # Max iterations — get final answer without tools
        response = await self.complete(working_messages)
        content = response.content or ""
        if content:
            words = content.split(" ")
            for i, word in enumerate(words):
                token = word if i == 0 else " " + word
                yield {"type": "token", "content": token}

    async def stream(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.3,
    ) -> AsyncIterator[str]:
        """Async generator yielding content chunks."""
        if self.is_ollama:
            async for chunk in self._stream_ollama(messages, temperature):
                yield chunk
        else:
            async for chunk in self._stream_openai(messages, temperature):
                yield chunk

    # ------------------------------------------------------------------
    # Ollama native
    # ------------------------------------------------------------------

    def _format_messages_ollama(self, messages: list[LLMMessage]) -> list[dict]:
        formatted = []
        for m in messages:
            msg: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls:
                msg["tool_calls"] = [
                    {"function": {"name": tc.get("function", tc).get("name", ""),
                                  "arguments": tc.get("function", tc).get("arguments", {})}}
                    for tc in m.tool_calls
                ]
            if m.role == "tool" and m.name:
                msg["tool_name"] = m.name
            formatted.append(msg)
        return formatted

    def _format_tools_ollama(self, tools: list[ToolDefinition]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    async def _complete_ollama_native(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None,
        temperature: float,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._format_messages_ollama(messages),
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = self._format_tools_ollama(tools)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        msg = data.get("message", {})
        tool_calls = None
        raw_tool_calls = msg.get("tool_calls")
        if raw_tool_calls:
            tool_calls = []
            for tc in raw_tool_calls:
                func = tc.get("function", {})
                tool_calls.append({
                    "function": {
                        "name": func.get("name", ""),
                        "arguments": func.get("arguments", {}),
                    }
                })

        return LLMResponse(
            content=msg.get("content", ""),
            tool_calls=tool_calls,
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            },
            finish_reason="tool_calls" if tool_calls else "stop",
        )

    async def _stream_ollama(
        self, messages: list[LLMMessage], temperature: float
    ) -> AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": self._format_messages_ollama(messages),
            "stream": True,
            "options": {"temperature": temperature},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
                headers=self._headers(),
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue

    # ------------------------------------------------------------------
    # OpenAI-compatible
    # ------------------------------------------------------------------

    def _format_messages_openai(self, messages: list[LLMMessage]) -> list[dict]:
        formatted = []
        for m in messages:
            msg: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls and m.role == "assistant":
                msg["tool_calls"] = [
                    {
                        "id": tc.get("id", f"call_{i}"),
                        "type": "function",
                        "function": {
                            "name": tc.get("function", tc).get("name", ""),
                            "arguments": json.dumps(tc.get("function", tc).get("arguments", {}))
                            if isinstance(tc.get("function", tc).get("arguments"), dict)
                            else tc.get("function", tc).get("arguments", "{}"),
                        },
                    }
                    for i, tc in enumerate(m.tool_calls)
                ]
            if m.role == "tool" and m.name:
                msg["tool_call_id"] = m.name
            formatted.append(msg)
        return formatted

    def _format_tools_openai(self, tools: list[ToolDefinition]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    async def _complete_openai_compat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolDefinition] | None,
        temperature: float,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self._format_messages_openai(messages),
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = self._format_tools_openai(tools)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data.get("choices", [{}])[0]
        msg = choice.get("message", {})

        tool_calls = None
        raw_tool_calls = msg.get("tool_calls")
        if raw_tool_calls:
            tool_calls = []
            for tc in raw_tool_calls:
                func = tc.get("function", {})
                args = func.get("arguments", "{}")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                tool_calls.append({
                    "id": tc.get("id", ""),
                    "function": {
                        "name": func.get("name", ""),
                        "arguments": args,
                    },
                })

        usage = data.get("usage", {})
        return LLMResponse(
            content=msg.get("content", "") or "",
            tool_calls=tool_calls,
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
            },
            finish_reason=choice.get("finish_reason", "stop"),
        )

    async def _stream_openai(
        self, messages: list[LLMMessage], temperature: float
    ) -> AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": self._format_messages_openai(messages),
            "temperature": temperature,
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                headers=self._headers(),
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue
