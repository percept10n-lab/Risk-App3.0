import asyncio
import json
from datetime import datetime
from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.fingerprinting.probes import PortScanner, ServiceProbe, OSDetector


server = BaseMCPServer(name="fingerprinting", version="1.0.0")
port_scanner = PortScanner()
service_probe = ServiceProbe()
os_detector = OSDetector()


@server.tool(
    name="port_scan",
    description="Scan for open ports on a target host. Uses conservative settings (top 100 ports, throttled).",
    input_schema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address",
            },
            "ports": {
                "type": "string",
                "description": "Port specification (e.g., '1-1024', '22,80,443', or 'top100')",
                "default": "top100",
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds",
                "default": 60,
            },
        },
        "required": ["target"],
    },
)
async def port_scan(target: str, ports: str = "top100", timeout: int = 60) -> dict:
    results = await port_scanner.scan(target, ports, timeout)
    return ToolResult(
        success=True,
        data=results,
        artifacts=[{
            "type": "raw_output",
            "tool": "port_scan",
            "target": target,
            "content": json.dumps(results, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"target": target, "open_ports": len(results.get("open_ports", []))},
    ).model_dump()


@server.tool(
    name="service_detection",
    description="Detect services and versions running on open ports of a target.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address",
            },
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "List of ports to probe (if empty, scans common ports first)",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds",
                "default": 60,
            },
        },
        "required": ["target"],
    },
)
async def service_detection(target: str, ports: list[int] | None = None, timeout: int = 60) -> dict:
    results = await service_probe.detect_services(target, ports, timeout)
    return ToolResult(
        success=True,
        data=results,
        artifacts=[{
            "type": "raw_output",
            "tool": "service_detection",
            "target": target,
            "content": json.dumps(results, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"target": target, "services_found": len(results.get("services", []))},
    ).model_dump()


@server.tool(
    name="os_fingerprint",
    description="Attempt OS fingerprinting on a target host.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address",
            },
        },
        "required": ["target"],
    },
)
async def os_fingerprint(target: str) -> dict:
    results = await os_detector.detect(target)
    return ToolResult(
        success=True,
        data=results,
        artifacts=[{
            "type": "raw_output",
            "tool": "os_fingerprint",
            "target": target,
            "content": json.dumps(results, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
    ).model_dump()


@server.tool(
    name="full_fingerprint",
    description="Run complete fingerprinting: port scan, service detection, and OS fingerprinting.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP address",
            },
            "timeout": {
                "type": "integer",
                "description": "Total timeout in seconds",
                "default": 120,
            },
        },
        "required": ["target"],
    },
)
async def full_fingerprint(target: str, timeout: int = 120) -> dict:
    # Step 1: Port scan
    port_results = await port_scanner.scan(target, "top100", timeout // 3)
    open_ports = [p["port"] for p in port_results.get("open_ports", [])]

    # Step 2: Service detection on open ports
    service_results = {}
    if open_ports:
        service_results = await service_probe.detect_services(target, open_ports, timeout // 3)

    # Step 3: OS detection
    os_results = await os_detector.detect(target)

    # Build exposure indicators
    exposure = {
        "wan_accessible": False,  # Can't determine from internal scan
        "admin_ui": any(p in open_ports for p in [80, 443, 8080, 8443, 9090]),
        "ssh_exposed": 22 in open_ports,
        "telnet_exposed": 23 in open_ports,
        "smb_exposed": 445 in open_ports,
        "upnp": 1900 in open_ports or 5000 in open_ports,
        "ftp_exposed": 21 in open_ports,
    }

    combined = {
        "target": target,
        "open_ports": port_results.get("open_ports", []),
        "services": service_results.get("services", []),
        "os": os_results,
        "exposure": exposure,
        "timestamp": datetime.utcnow().isoformat(),
    }

    return ToolResult(
        success=True,
        data=combined,
        artifacts=[{
            "type": "raw_output",
            "tool": "full_fingerprint",
            "target": target,
            "content": json.dumps(combined, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={
            "target": target,
            "open_port_count": len(open_ports),
            "service_count": len(service_results.get("services", [])),
            "os_guess": os_results.get("os_guess", "unknown"),
        },
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
