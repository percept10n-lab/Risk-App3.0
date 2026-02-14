import json
import asyncio
import subprocess
from typing import Any
import structlog

logger = structlog.get_logger()


class MCPClient:
    def __init__(self, server_path: str, server_name: str):
        self.server_path = server_path
        self.server_name = server_name
        self.process: subprocess.Popen | None = None

    async def start(self):
        self.process = subprocess.Popen(
            ["python", self.server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.info("MCP server started", server=self.server_name, pid=self.process.pid)

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        if not self.process or self.process.poll() is not None:
            await self.start()

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()

            response_line = self.process.stdout.readline()
            if response_line:
                return json.loads(response_line)
            return {"error": "No response from MCP server"}
        except Exception as e:
            logger.error("MCP call failed", server=self.server_name, tool=tool_name, error=str(e))
            return {"error": str(e)}

    async def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            logger.info("MCP server stopped", server=self.server_name)

    async def list_tools(self) -> list[dict]:
        if not self.process or self.process.poll() is not None:
            await self.start()

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }

        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
            response_line = self.process.stdout.readline()
            if response_line:
                result = json.loads(response_line)
                return result.get("result", {}).get("tools", [])
            return []
        except Exception as e:
            logger.error("Failed to list tools", server=self.server_name, error=str(e))
            return []
