import asyncio
import json
from datetime import datetime
from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult
from mcp_servers.vuln_scanning.checks.http_checks import HTTPSecurityChecker
from mcp_servers.vuln_scanning.checks.tls_checks import TLSChecker
from mcp_servers.vuln_scanning.checks.ssh_checks import SSHChecker
from mcp_servers.vuln_scanning.checks.dns_checks import DNSChecker
from mcp_servers.vuln_scanning.normalizer import FindingNormalizer

server = BaseMCPServer(name="vuln-scanning", version="1.0.0")
normalizer = FindingNormalizer()


@server.tool(
    name="http_security_check",
    description="Check HTTP security headers and common web misconfigurations on a target.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target IP or hostname"},
            "port": {"type": "integer", "description": "HTTP port", "default": 80},
            "use_tls": {"type": "boolean", "default": False},
        },
        "required": ["target"],
    },
)
async def http_security_check(target: str, port: int = 80, use_tls: bool = False) -> dict:
    checker = HTTPSecurityChecker()
    findings = await checker.check(target, port, use_tls)
    normalized = normalizer.normalize_batch(findings, "http_security", target)
    return ToolResult(
        success=True,
        data={"findings": normalized, "target": target, "port": port},
        artifacts=[{
            "type": "raw_output", "tool": "http_security_check", "target": f"{target}:{port}",
            "content": json.dumps(normalized, indent=2), "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"finding_count": len(normalized)},
    ).model_dump()


@server.tool(
    name="tls_check",
    description="Analyze TLS/SSL configuration on a target port.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target IP or hostname"},
            "port": {"type": "integer", "description": "TLS port", "default": 443},
        },
        "required": ["target"],
    },
)
async def tls_check(target: str, port: int = 443) -> dict:
    checker = TLSChecker()
    findings = await checker.check(target, port)
    normalized = normalizer.normalize_batch(findings, "tls_check", target)
    return ToolResult(
        success=True,
        data={"findings": normalized, "target": target, "port": port},
        artifacts=[{
            "type": "raw_output", "tool": "tls_check", "target": f"{target}:{port}",
            "content": json.dumps(normalized, indent=2), "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"finding_count": len(normalized)},
    ).model_dump()


@server.tool(
    name="ssh_check",
    description="Check SSH server configuration and hardening.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target IP or hostname"},
            "port": {"type": "integer", "description": "SSH port", "default": 22},
        },
        "required": ["target"],
    },
)
async def ssh_check(target: str, port: int = 22) -> dict:
    checker = SSHChecker()
    findings = await checker.check(target, port)
    normalized = normalizer.normalize_batch(findings, "ssh_check", target)
    return ToolResult(
        success=True,
        data={"findings": normalized, "target": target, "port": port},
        artifacts=[{
            "type": "raw_output", "tool": "ssh_check", "target": f"{target}:{port}",
            "content": json.dumps(normalized, indent=2), "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"finding_count": len(normalized)},
    ).model_dump()


@server.tool(
    name="dns_check",
    description="Check DNS configuration and security.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target DNS server IP"},
            "port": {"type": "integer", "description": "DNS port", "default": 53},
        },
        "required": ["target"],
    },
)
async def dns_check(target: str, port: int = 53) -> dict:
    checker = DNSChecker()
    findings = await checker.check(target, port)
    normalized = normalizer.normalize_batch(findings, "dns_check", target)
    return ToolResult(
        success=True,
        data={"findings": normalized, "target": target, "port": port},
        artifacts=[{
            "type": "raw_output", "tool": "dns_check", "target": f"{target}:{port}",
            "content": json.dumps(normalized, indent=2), "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"finding_count": len(normalized)},
    ).model_dump()


@server.tool(
    name="full_vuln_scan",
    description="Run all vulnerability checks against a target based on its open ports.",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "open_ports": {"type": "array", "items": {"type": "integer"}, "description": "List of open ports to check"},
        },
        "required": ["target", "open_ports"],
    },
)
async def full_vuln_scan(target: str, open_ports: list[int]) -> dict:
    all_findings = []

    # HTTP checks
    for port in open_ports:
        if port in (80, 8080, 8000, 8008, 8888, 3000, 9090):
            checker = HTTPSecurityChecker()
            findings = await checker.check(target, port, use_tls=False)
            all_findings.extend(normalizer.normalize_batch(findings, "http_security", target))
        elif port in (443, 8443, 4443):
            checker = HTTPSecurityChecker()
            findings = await checker.check(target, port, use_tls=True)
            all_findings.extend(normalizer.normalize_batch(findings, "http_security", target))

    # TLS checks
    for port in open_ports:
        if port in (443, 8443, 4443, 993, 995, 465, 636):
            checker = TLSChecker()
            findings = await checker.check(target, port)
            all_findings.extend(normalizer.normalize_batch(findings, "tls_check", target))

    # SSH check
    if 22 in open_ports:
        checker = SSHChecker()
        findings = await checker.check(target, 22)
        all_findings.extend(normalizer.normalize_batch(findings, "ssh_check", target))

    # DNS check
    if 53 in open_ports:
        checker = DNSChecker()
        findings = await checker.check(target, 53)
        all_findings.extend(normalizer.normalize_batch(findings, "dns_check", target))

    # Deduplicate
    all_findings = normalizer.deduplicate(all_findings)

    return ToolResult(
        success=True,
        data={"findings": all_findings, "target": target},
        artifacts=[{
            "type": "raw_output", "tool": "full_vuln_scan", "target": target,
            "content": json.dumps(all_findings, indent=2), "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"finding_count": len(all_findings), "ports_checked": open_ports},
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
