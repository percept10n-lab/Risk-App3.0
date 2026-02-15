import asyncio
import json
from datetime import datetime
from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import ToolResult, AssetResult
from mcp_servers.asset_discovery.scanner import NetworkScanner
from mcp_servers.asset_discovery.passive import PassiveDiscovery


server = BaseMCPServer(name="asset-discovery", version="1.0.0")
scanner = NetworkScanner()
passive = PassiveDiscovery()


@server.tool(
    name="arp_scan",
    description="Perform ARP scan to discover hosts on a local subnet. Returns list of discovered hosts with IP, MAC, hostname, and vendor.",
    input_schema={
        "type": "object",
        "properties": {
            "subnet": {
                "type": "string",
                "description": "Target subnet in CIDR notation (e.g., 192.168.178.0/24)",
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds",
                "default": 30,
            },
        },
        "required": ["subnet"],
    },
)
async def arp_scan(subnet: str, timeout: int = 30) -> dict:
    results = await scanner.arp_scan(subnet, timeout)
    return ToolResult(
        success=True,
        data={"hosts": [r.model_dump() for r in results]},
        artifacts=[{
            "type": "raw_output",
            "tool": "arp_scan",
            "target": subnet,
            "content": json.dumps([r.model_dump() for r in results], indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"subnet": subnet, "host_count": len(results)},
    ).model_dump()


@server.tool(
    name="ping_sweep",
    description="Perform ICMP ping sweep to discover live hosts on a subnet.",
    input_schema={
        "type": "object",
        "properties": {
            "subnet": {
                "type": "string",
                "description": "Target subnet in CIDR notation",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds",
                "default": 30,
            },
        },
        "required": ["subnet"],
    },
)
async def ping_sweep(subnet: str, timeout: int = 30) -> dict:
    results = await scanner.ping_sweep(subnet, timeout)
    return ToolResult(
        success=True,
        data={"hosts": [r.model_dump() for r in results]},
        artifacts=[{
            "type": "raw_output",
            "tool": "ping_sweep",
            "target": subnet,
            "content": json.dumps([r.model_dump() for r in results], indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"subnet": subnet, "host_count": len(results)},
    ).model_dump()


@server.tool(
    name="mdns_discover",
    description="Discover devices advertising services via mDNS (Bonjour/Avahi).",
    input_schema={
        "type": "object",
        "properties": {
            "duration": {
                "type": "integer",
                "description": "Discovery duration in seconds",
                "default": 10,
            },
        },
    },
)
async def mdns_discover(duration: int = 10) -> dict:
    results = await passive.mdns_discover(duration)
    return ToolResult(
        success=True,
        data={"services": results},
        artifacts=[{
            "type": "raw_output",
            "tool": "mdns_discover",
            "target": "local_network",
            "content": json.dumps(results, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"service_count": len(results)},
    ).model_dump()


@server.tool(
    name="ssdp_discover",
    description="Discover UPnP devices via SSDP (Simple Service Discovery Protocol).",
    input_schema={
        "type": "object",
        "properties": {
            "timeout": {
                "type": "integer",
                "description": "Discovery timeout in seconds",
                "default": 5,
            },
        },
    },
)
async def ssdp_discover(timeout: int = 5) -> dict:
    results = await passive.ssdp_discover(timeout)
    return ToolResult(
        success=True,
        data={"devices": results},
        artifacts=[{
            "type": "raw_output",
            "tool": "ssdp_discover",
            "target": "local_network",
            "content": json.dumps(results, indent=2),
            "timestamp": datetime.utcnow().isoformat(),
        }],
        metadata={"device_count": len(results)},
    ).model_dump()


@server.tool(
    name="full_discovery",
    description="Run complete asset discovery combining ARP scan, ping sweep, mDNS, and SSDP. Merges results into a unified asset list.",
    input_schema={
        "type": "object",
        "properties": {
            "subnet": {
                "type": "string",
                "description": "Target subnet in CIDR notation",
            },
            "timeout": {
                "type": "integer",
                "description": "Total timeout in seconds",
                "default": 60,
            },
        },
        "required": ["subnet"],
    },
)
async def full_discovery(subnet: str, timeout: int = 60) -> dict:
    arp_results, ping_results, mdns_results, ssdp_results = await asyncio.gather(
        scanner.arp_scan(subnet, timeout=timeout // 2),
        scanner.ping_sweep(subnet, timeout=timeout // 2),
        passive.mdns_discover(duration=min(10, timeout // 4)),
        passive.ssdp_discover(timeout=min(5, timeout // 4)),
        return_exceptions=True,
    )

    # Merge results by IP
    hosts: dict[str, dict] = {}

    if isinstance(arp_results, list):
        for r in arp_results:
            ip = r.ip_address
            hosts[ip] = {
                "ip_address": ip,
                "mac_address": r.mac_address,
                "hostname": r.hostname,
                "vendor": r.vendor,
                "discovery_methods": ["arp"],
            }

    if isinstance(ping_results, list):
        for r in ping_results:
            ip = r.ip_address
            if ip in hosts:
                hosts[ip]["discovery_methods"].append("ping")
                if r.hostname and not hosts[ip].get("hostname"):
                    hosts[ip]["hostname"] = r.hostname
            else:
                hosts[ip] = {
                    "ip_address": ip,
                    "mac_address": r.mac_address,
                    "hostname": r.hostname,
                    "vendor": r.vendor,
                    "discovery_methods": ["ping"],
                }

    if isinstance(mdns_results, list):
        for svc in mdns_results:
            ip = svc.get("ip")
            if ip and ip in hosts:
                hosts[ip].setdefault("mdns_services", []).append(svc)
                hosts[ip]["discovery_methods"].append("mdns")
                if svc.get("hostname") and not hosts[ip].get("hostname"):
                    hosts[ip]["hostname"] = svc["hostname"]

    if isinstance(ssdp_results, list):
        for dev in ssdp_results:
            ip = dev.get("ip")
            if ip and ip in hosts:
                hosts[ip].setdefault("ssdp_info", dev)
                hosts[ip]["discovery_methods"].append("ssdp")

    merged = list(hosts.values())

    return ToolResult(
        success=True,
        data={"hosts": merged, "summary": {
            "total_hosts": len(merged),
            "arp_found": len(arp_results) if isinstance(arp_results, list) else 0,
            "ping_found": len(ping_results) if isinstance(ping_results, list) else 0,
            "mdns_services": len(mdns_results) if isinstance(mdns_results, list) else 0,
            "ssdp_devices": len(ssdp_results) if isinstance(ssdp_results, list) else 0,
        }},
        artifacts=[{
            "type": "raw_output",
            "tool": "full_discovery",
            "target": subnet,
            "content": json.dumps(merged, indent=2, default=str),
            "timestamp": datetime.utcnow().isoformat(),
        }],
    ).model_dump()


if __name__ == "__main__":
    asyncio.run(server.run_stdio())
