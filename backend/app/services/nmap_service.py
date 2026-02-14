import json
import asyncio
import ipaddress
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
from app.services.finding_service import FindingService
import structlog

logger = structlog.get_logger()

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

SCAN_PROFILES = {
    # Active Scans
    "tcp_connect": {
        "name": "TCP Connect",
        "args": "-sT",
        "category": "active",
        "risk": "low",
        "description": "Full TCP handshake scan — reliable, no root needed",
        "timeout": 120,
    },
    "quick_scan": {
        "name": "Quick Scan",
        "args": "-sT -F",
        "category": "active",
        "risk": "low",
        "description": "Fast scan of top 100 ports",
        "timeout": 60,
    },
    "version_detect": {
        "name": "Version Detection",
        "args": "-sV --version-intensity 5",
        "category": "active",
        "risk": "medium",
        "description": "Probe open ports for service/version info",
        "timeout": 180,
    },
    # Reconnaissance
    "ping_sweep": {
        "name": "Ping Sweep",
        "args": "-sn",
        "category": "passive",
        "risk": "low",
        "description": "Host discovery only — no port scan",
        "timeout": 60,
    },
    "dns_service": {
        "name": "DNS Enumeration",
        "args": "-sT -sV -p 53 --script dns-nsid,dns-service-discovery,dns-recursion",
        "category": "passive",
        "risk": "low",
        "description": "DNS service enumeration and recursion check",
        "timeout": 120,
    },
    # Offensive Scans
    "vuln_scripts": {
        "name": "Vulnerability Scripts",
        "args": "--script vuln",
        "category": "offensive",
        "risk": "high",
        "description": "Run NSE vulnerability detection scripts",
        "timeout": 300,
    },
    "full_port": {
        "name": "Full Port Scan",
        "args": "-p- -sT",
        "category": "offensive",
        "risk": "high",
        "description": "Scan all 65535 TCP ports",
        "timeout": 600,
    },
    "service_all": {
        "name": "Full Service Detection",
        "args": "-sT -sV -p- --version-intensity 3",
        "category": "offensive",
        "risk": "medium",
        "description": "All ports with service/version detection",
        "timeout": 900,
    },
}

HIGH_RISK_PORTS = {
    23: ("Telnet", "high", "Telnet transmits data in cleartext including credentials"),
    445: ("SMB", "high", "SMB file sharing exposed — risk of lateral movement"),
    3389: ("RDP", "high", "Remote Desktop exposed — brute-force and exploit target"),
    5900: ("VNC", "high", "VNC remote access exposed — often weakly authenticated"),
    3306: ("MySQL", "high", "MySQL database port exposed to network"),
    21: ("FTP", "high", "FTP transmits credentials in cleartext"),
    1433: ("MSSQL", "high", "Microsoft SQL Server exposed"),
    5432: ("PostgreSQL", "high", "PostgreSQL database exposed"),
    6379: ("Redis", "high", "Redis — often unauthenticated by default"),
    27017: ("MongoDB", "high", "MongoDB — often unauthenticated by default"),
}

MEDIUM_RISK_PORTS = {
    25: ("SMTP", "medium"),
    53: ("DNS", "medium"),
    110: ("POP3", "medium"),
    143: ("IMAP", "medium"),
    161: ("SNMP", "medium"),
    389: ("LDAP", "medium"),
    8080: ("HTTP-Alt", "medium"),
    8443: ("HTTPS-Alt", "medium"),
}


class NmapService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)
        self.finding_service = FindingService(db)

    def validate_scope(self, target: str) -> bool:
        """Validate target is in RFC 1918 private range. Supports single IP or CIDR notation."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            return any(net.subnet_of(priv) for priv in PRIVATE_NETWORKS)
        except ValueError:
            try:
                ip = ipaddress.ip_address(target)
                return any(ip in net for net in PRIVATE_NETWORKS)
            except ValueError:
                return False

    async def execute_scan(
        self, profile_id: str, asset_id: str | None = None, target: str | None = None,
        run_id: str | None = None, params: dict | None = None,
    ) -> dict:
        """Execute an nmap scan against an asset or free target IP."""
        if profile_id not in SCAN_PROFILES:
            return {"status": "error", "error": f"Unknown scan profile: {profile_id}"}

        profile = SCAN_PROFILES[profile_id]

        # Resolve target IP
        is_cidr = target and "/" in target if target else False
        asset = None
        if asset_id:
            result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            if not asset:
                return {"status": "error", "error": f"Asset not found: {asset_id}"}
            target = asset.ip_address
        elif target:
            if not is_cidr:
                # Free target — try to find matching asset by IP
                result = await self.db.execute(select(Asset).where(Asset.ip_address == target))
                asset = result.scalar_one_or_none()
                if asset:
                    asset_id = asset.id
        else:
            return {"status": "error", "error": "Either asset_id or target IP must be provided"}

        if not self.validate_scope(target):
            return {"status": "error", "error": f"Target {target} is outside allowed scope (RFC 1918 only)"}

        logger.info("Executing nmap scan", profile=profile_id, target=target)

        await self.audit_trail.log(
            event_type="action", entity_type="nmap_scan",
            entity_id=asset_id or target, actor="user",
            action=f"nmap_{profile_id}",
            run_id=run_id,
            new_value={"target": target, "profile": profile_id, "params": params or {}},
        )

        # Run nmap
        try:
            nm = await self._run_nmap(target, profile)
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Scan timed out after {profile['timeout']}s"}
        except Exception as e:
            logger.error("Nmap scan failed", profile=profile_id, error=str(e))
            return {"status": "error", "error": str(e)}

        # Parse results
        raw_findings = self._parse_results(nm, target, profile_id)

        # Store findings — for CIDR scans, match each host IP to an asset
        created = 0
        findings_list = []
        if is_cidr:
            # Build IP→asset lookup for CIDR results
            all_assets_result = await self.db.execute(select(Asset))
            all_assets = {a.ip_address: a for a in all_assets_result.scalars().all()}
            for raw in raw_findings:
                host_ip = raw.get("_host_ip")
                matched_asset = all_assets.get(host_ip) if host_ip else None
                if matched_asset:
                    finding_data = {
                        "asset_id": matched_asset.id,
                        "run_id": run_id,
                        "title": raw["title"],
                        "description": raw.get("description", ""),
                        "severity": raw.get("severity", "info"),
                        "category": raw.get("category", "exposure"),
                        "source_tool": f"nmap_{profile_id}",
                        "source_check": raw.get("source_check", profile_id),
                        "cwe_id": raw.get("cwe_id"),
                        "evidence_artifact_ids": [],
                        "raw_output_snippet": raw.get("evidence", ""),
                        "remediation": raw.get("remediation"),
                    }
                    finding, is_new = await self.finding_service.create_deduplicated(finding_data)
                    if is_new:
                        created += 1
                    raw["finding_id"] = finding.id
                    raw["is_new"] = is_new
                    raw["matched_asset_id"] = matched_asset.id
                findings_list.append(raw)
        elif asset_id:
            for raw in raw_findings:
                finding_data = {
                    "asset_id": asset_id,
                    "run_id": run_id,
                    "title": raw["title"],
                    "description": raw.get("description", ""),
                    "severity": raw.get("severity", "info"),
                    "category": raw.get("category", "exposure"),
                    "source_tool": f"nmap_{profile_id}",
                    "source_check": raw.get("source_check", profile_id),
                    "cwe_id": raw.get("cwe_id"),
                    "evidence_artifact_ids": [],
                    "raw_output_snippet": raw.get("evidence", ""),
                    "remediation": raw.get("remediation"),
                }
                finding, is_new = await self.finding_service.create_deduplicated(finding_data)
                if is_new:
                    created += 1
                raw["finding_id"] = finding.id
                raw["is_new"] = is_new
                findings_list.append(raw)
        else:
            findings_list = raw_findings

        # Store artifact
        await self.artifact_store.store(
            content=json.dumps({"scan_results": nm.get("raw", {}), "findings": findings_list}, indent=2, default=str),
            artifact_type="raw_output",
            tool_name=f"nmap_{profile_id}",
            target=target,
            run_id=run_id,
            command=f"nmap {profile['args']} {target}",
            parameters={"profile": profile_id, "target": target, **(params or {})},
        )

        # Extract raw host data for direct display
        raw_hosts = nm.get("raw", {}).get("hosts", {})
        scan_details = []
        for host, host_data in raw_hosts.items():
            host_entry = {"host": host, "state": host_data.get("state", "unknown"), "ports": [], "os": []}
            for proto, ports in host_data.get("protocols", {}).items():
                for port_str, port_info in ports.items():
                    host_entry["ports"].append({
                        "port": int(port_str),
                        "protocol": proto,
                        "state": port_info.get("state", ""),
                        "service": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "scripts": {k: v[:500] for k, v in port_info.get("script", {}).items()} if port_info.get("script") else {},
                    })
            for osmatch in host_data.get("osmatch", []):
                host_entry["os"].append({"name": osmatch.get("name", ""), "accuracy": osmatch.get("accuracy", "")})
            scan_details.append(host_entry)

        command_line = nm.get("raw", {}).get("command_line", f"nmap {profile['args']} {target}")

        return {
            "status": "completed",
            "profile": profile_id,
            "target": target,
            "asset_id": asset_id,
            "command_line": command_line,
            "scan_details": scan_details,
            "findings": findings_list,
            "findings_created": created,
            "total_findings": len(findings_list),
        }

    async def _run_nmap(self, target: str, profile: dict) -> dict:
        """Run nmap scan in executor with timeout."""
        import nmap

        loop = asyncio.get_event_loop()
        timeout = profile.get("timeout", 120)

        def _scan():
            nm = nmap.PortScanner()
            args = profile["args"]
            nm.scan(hosts=target, arguments=args)
            return {
                "raw": {
                    "command_line": nm.command_line(),
                    "scaninfo": nm.scaninfo(),
                    "all_hosts": nm.all_hosts(),
                    "hosts": {},
                },
                "scanner": nm,
            }

        result = await asyncio.wait_for(
            loop.run_in_executor(None, _scan),
            timeout=timeout,
        )

        nm = result["scanner"]
        for host in nm.all_hosts():
            host_data = {
                "state": nm[host].state(),
                "protocols": {},
            }
            for proto in nm[host].all_protocols():
                ports = {}
                for port in nm[host][proto].keys():
                    port_info = nm[host][proto][port]
                    ports[str(port)] = {
                        "state": port_info.get("state", ""),
                        "name": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "script": port_info.get("script", {}),
                    }
                host_data["protocols"][proto] = ports

            # OS detection
            if hasattr(nm[host], "osmatch") or "osmatch" in nm[host]:
                try:
                    host_data["osmatch"] = nm[host].get("osmatch", [])
                except Exception:
                    host_data["osmatch"] = []

            result["raw"]["hosts"][host] = host_data

        return result

    def _parse_results(self, nm_result: dict, target: str, profile_id: str) -> list[dict]:
        """Parse nmap results into finding dicts."""
        findings = []
        raw = nm_result.get("raw", {})

        for host, host_data in raw.get("hosts", {}).items():
            # Port findings
            for proto, ports in host_data.get("protocols", {}).items():
                for port_str, port_info in ports.items():
                    port = int(port_str)
                    if port_info.get("state") == "open":
                        f = self._port_to_finding(host, port, proto, port_info, profile_id)
                        f["_host_ip"] = host
                        findings.append(f)

                    # Script findings
                    for script_name, script_output in port_info.get("script", {}).items():
                        script_finding = self._script_to_finding(host, port, script_name, script_output, profile_id)
                        if script_finding:
                            script_finding["_host_ip"] = host
                            findings.append(script_finding)

            # OS findings
            for osmatch in host_data.get("osmatch", []):
                f = self._os_to_finding(host, osmatch, profile_id)
                f["_host_ip"] = host
                findings.append(f)

        return findings

    def _port_to_finding(self, host: str, port: int, proto: str, info: dict, profile_id: str) -> dict:
        """Convert open port to finding dict."""
        service = info.get("name", "unknown")
        product = info.get("product", "")
        version = info.get("version", "")
        service_str = f"{service}"
        if product:
            service_str += f" ({product}"
            if version:
                service_str += f" {version}"
            service_str += ")"

        # Determine severity
        if port in HIGH_RISK_PORTS:
            name, severity, desc = HIGH_RISK_PORTS[port]
            return {
                "title": f"Open port {port}/{proto} — {name} on {host}",
                "description": desc,
                "severity": severity,
                "category": "exposure",
                "source_check": f"port_{port}",
                "evidence": f"Port {port}/{proto}: {service_str} (state: open)",
                "remediation": f"Close port {port} or restrict access via firewall rules",
            }

        if port in MEDIUM_RISK_PORTS:
            name, severity = MEDIUM_RISK_PORTS[port]
            return {
                "title": f"Open port {port}/{proto} — {name} on {host}",
                "description": f"{name} service detected on port {port}",
                "severity": severity,
                "category": "exposure",
                "source_check": f"port_{port}",
                "evidence": f"Port {port}/{proto}: {service_str} (state: open)",
                "remediation": f"Verify port {port} ({name}) is required and properly secured",
            }

        # Standard ports
        severity = "low" if port > 1024 else "info"
        return {
            "title": f"Open port {port}/{proto} — {service} on {host}",
            "description": f"Service {service_str} detected on port {port}",
            "severity": severity,
            "category": "exposure",
            "source_check": f"port_{port}",
            "evidence": f"Port {port}/{proto}: {service_str} (state: open)",
        }

    def _script_to_finding(self, host: str, port: int, script_name: str, output: str, profile_id: str) -> dict | None:
        """Convert NSE script output to finding dict."""
        if not output:
            return None

        is_vuln = "VULNERABLE" in output.upper()
        severity = "high" if is_vuln else "info"

        if severity == "info" and "ERROR" not in output.upper():
            return None

        return {
            "title": f"NSE {script_name} — port {port} on {host}",
            "description": f"NSE script '{script_name}' result on port {port}",
            "severity": severity,
            "category": "vuln" if is_vuln else "exposure",
            "source_check": f"nse_{script_name}",
            "evidence": output[:2000],
            "remediation": f"Investigate and remediate vulnerability detected by {script_name}" if is_vuln else None,
        }

    def _os_to_finding(self, host: str, osmatch: dict, profile_id: str) -> dict:
        """Convert OS match to finding dict."""
        name = osmatch.get("name", "Unknown OS")
        accuracy = osmatch.get("accuracy", "0")
        return {
            "title": f"OS detected: {name} on {host}",
            "description": f"Operating system identified with {accuracy}% confidence: {name}",
            "severity": "info",
            "category": "exposure",
            "source_check": "os_detect",
            "evidence": f"OS match: {name} (accuracy: {accuracy}%)",
        }

    async def verify_with_vuln_scan(
        self, asset_id: str, finding_ids: list[str] | None = None, run_id: str | None = None
    ) -> dict:
        """Verify nmap findings with targeted vulnerability checks."""
        from app.services.pentest_service import PentestService

        result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return {"status": "error", "error": f"Asset not found: {asset_id}"}

        # Get nmap findings for this asset
        query = select(Finding).where(
            Finding.asset_id == asset_id,
            Finding.source_tool.like("nmap_%"),
        )
        if finding_ids:
            query = query.where(Finding.id.in_(finding_ids))
        fres = await self.db.execute(query)
        nmap_findings = list(fres.scalars().all())

        if not nmap_findings:
            return {"status": "completed", "message": "No nmap findings to verify", "results": []}

        await self.audit_trail.log(
            event_type="action", entity_type="nmap_verify",
            entity_id=asset_id, actor="user",
            action="nmap_verify",
            run_id=run_id,
            new_value={"finding_count": len(nmap_findings)},
        )

        # Determine which verification checks to run based on open ports
        pentest = PentestService(self.db)
        target = asset.ip_address
        verification_results = []

        # Collect ports from findings
        has_http = False
        has_tls = False
        has_ssh = False

        for f in nmap_findings:
            title_lower = f.title.lower()
            if any(kw in title_lower for kw in ["80/", "8080/", "http", "443/"]):
                has_http = True
            if any(kw in title_lower for kw in ["443/", "tls", "ssl", "8443/"]):
                has_tls = True
            if "22/" in title_lower or "ssh" in title_lower:
                has_ssh = True

        # Run targeted checks
        checks_run = []
        if has_http:
            try:
                res = await pentest.execute_action("http_headers", target, run_id)
                verification_results.append({"check": "http_headers", "result": res})
                checks_run.append("http_headers")
            except Exception as e:
                verification_results.append({"check": "http_headers", "error": str(e)})

        if has_tls:
            try:
                res = await pentest.execute_action("tls_check", target, run_id)
                verification_results.append({"check": "tls_check", "result": res})
                checks_run.append("tls_check")
            except Exception as e:
                verification_results.append({"check": "tls_check", "error": str(e)})

        if has_ssh:
            try:
                res = await pentest.execute_action("ssh_hardening", target, run_id)
                verification_results.append({"check": "ssh_hardening", "result": res})
                checks_run.append("ssh_hardening")
            except Exception as e:
                verification_results.append({"check": "ssh_hardening", "error": str(e)})

        return {
            "status": "completed",
            "asset_id": asset_id,
            "nmap_findings_checked": len(nmap_findings),
            "checks_run": checks_run,
            "results": verification_results,
        }

    async def assess_risk(
        self, asset_id: str, finding_ids: list[str] | None = None, run_id: str | None = None
    ) -> dict:
        """Assess risk for nmap findings by delegating to RiskAnalysisService."""
        from app.services.risk_analysis_service import RiskAnalysisService

        service = RiskAnalysisService(self.db)
        result = await service.run_risk_analysis(asset_id=asset_id, run_id=run_id)
        return result
