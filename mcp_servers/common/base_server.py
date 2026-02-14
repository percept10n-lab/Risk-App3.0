import json
import sys
from typing import Any, Callable
import structlog

logger = structlog.get_logger()


class BaseMCPServer:
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.tools: dict[str, dict] = {}
        self._handlers: dict[str, Callable] = {}

    def tool(self, name: str, description: str, input_schema: dict):
        def decorator(func: Callable):
            self.tools[name] = {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }
            self._handlers[name] = func
            return func
        return decorator

    async def handle_request(self, request: dict) -> dict:
        method = request.get("method", "")
        request_id = request.get("id", 1)

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": self.version},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": list(self.tools.values())},
            }

        if method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            handler = self._handlers.get(tool_name)
            if not handler:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            try:
                result = await handler(**arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
                }
            except Exception as e:
                logger.error("Tool execution failed", tool=tool_name, error=str(e))
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }

    async def run_stdio(self):
        logger.info("MCP server starting", name=self.name, version=self.version)
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                request = json.loads(line.strip())
                response = await self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                continue
            except KeyboardInterrupt:
                break
        logger.info("MCP server stopped", name=self.name)
