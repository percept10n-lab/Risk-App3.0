import json
import asyncio
import re
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.finding import Finding
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
from app.services.finding_service import FindingService
from app.api.ws import manager
import structlog

logger = structlog.get_logger()

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

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
    111: ("IMAP", "medium"),
    143: ("IMAP", "medium"),
    161: ("SNMP", "medium"),
    389: ("LDAP", "medium"),
    8080: ("HTTP-Alt", "medium"),
    8443: ("HTTPS-Alt", "medium"),
}

# Dangerous nmap argument patterns that must be blocked
BLOCKED_ARG_PATTERNS = [
    (r"--resume", "Cannot use --resume"),
    (r"-iL\b", "Cannot use -iL (input from file)"),
    (r"-oN\b", "Cannot use -oN (output to file)"),
    (r"-oG\b", "Cannot use -oG (output to file)"),
    (r"-oS\b", "Cannot use -oS (output to file)"),
    (r"-oA\b", "Cannot use -oA (output to file)"),
    (r"[>;|]", "Shell redirects/pipes are not allowed"),
    (r"`", "Backticks are not allowed"),
    (r"\$\(", "Command substitution is not allowed"),
]

# Pipeline step names for progress tracking
PIPELINE_STEPS = [
    "nmap_scan",
    "asset_import",
    "store_findings",
    "vuln_assessment",
    "threat_modeling",
    "mitre_mapping",
    "risk_analysis",
]


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

    @staticmethod
    def validate_nmap_args(args: str) -> tuple[bool, str]:
        """Validate nmap arguments, blocking dangerous patterns."""
        for pattern, message in BLOCKED_ARG_PATTERNS:
            if re.search(pattern, args):
                return False, message
        return True, "ok"

    async def _run_nmap_with_streaming(
        self, target: str, nmap_args: str, run_id: str | None = None, timeout: int = 600
    ) -> dict:
        """Run nmap as subprocess, streaming stderr to WebSocket and capturing XML from stdout."""
        cmd_parts = ["nmap"] + nmap_args.split() + [target, "-oX", "-"]
        logger.info("Running nmap", command=" ".join(cmd_parts), run_id=run_id)

        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        xml_chunks = []
        stderr_lines = []

        async def read_stderr():
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                stderr_lines.append(text)
                if run_id:
                    await manager.broadcast(run_id, {"type": "nmap_output", "line": text})

        async def read_stdout():
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                xml_chunks.append(chunk)

        try:
            await asyncio.wait_for(
                asyncio.gather(read_stderr(), read_stdout(), process.wait()),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise asyncio.TimeoutError(f"Nmap scan timed out after {timeout}s")

        if process.returncode != 0 and not xml_chunks:
            error_text = "\n".join(stderr_lines[-10:])
            raise RuntimeError(f"Nmap exited with code {process.returncode}: {error_text}")

        xml_bytes = b"".join(xml_chunks)
        result = self._parse_xml_output(xml_bytes)

        # Send the command line used to console
        cmd_line = f"nmap {nmap_args} {target}"
        if run_id:
            await manager.broadcast(run_id, {"type": "nmap_output", "line": f"\n$ {cmd_line}"})
            await manager.broadcast(run_id, {
                "type": "nmap_output",
                "line": f"Scan complete — {len(result.get('hosts', {}))} host(s) found",
            })

        result["command_line"] = cmd_line
        return result

    def _parse_xml_output(self, xml_bytes: bytes) -> dict:
        """Parse nmap XML output into structured dict."""
        result = {"hosts": {}, "scaninfo": {}, "all_hosts": []}

        if not xml_bytes.strip():
            return result

        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as e:
            logger.error("Failed to parse nmap XML", error=str(e))
            return result

        # Scan info
        for si in root.findall("scaninfo"):
            result["scaninfo"][si.get("protocol", "tcp")] = {
                "method": si.get("type", ""),
                "services": si.get("services", ""),
            }

        # Hosts
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            if not ip:
                continue

            result["all_hosts"].append(ip)

            status_el = host_el.find("status")
            host_data = {
                "state": status_el.get("state", "unknown") if status_el is not None else "unknown",
                "protocols": {},
                "osmatch": [],
            }

            # Ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    proto = port_el.get("protocol", "tcp")
                    portid = port_el.get("portid", "0")

                    state_el = port_el.find("state")
                    service_el = port_el.find("service")

                    port_info = {
                        "state": state_el.get("state", "") if state_el is not None else "",
                        "name": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                        "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                        "script": {},
                    }

                    for script_el in port_el.findall("script"):
                        sid = script_el.get("id", "")
                        sout = script_el.get("output", "")
                        if sid:
                            port_info["script"][sid] = sout

                    if proto not in host_data["protocols"]:
                        host_data["protocols"][proto] = {}
                    host_data["protocols"][proto][portid] = port_info

            # OS detection
            for osmatch_el in host_el.findall(".//osmatch"):
                host_data["osmatch"].append({
                    "name": osmatch_el.get("name", ""),
                    "accuracy": osmatch_el.get("accuracy", "0"),
                })

            # Hostnames
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                names = []
                for hn in hostnames_el.findall("hostname"):
                    n = hn.get("name", "")
                    if n:
                        names.append(n)
                if names:
                    host_data["hostnames"] = names

            result["hosts"][ip] = host_data

        return result

    def _parse_results(self, nm_result: dict, target: str, source_tool: str = "nmap_custom") -> list[dict]:
        """Parse nmap results into finding dicts."""
        findings = []

        for host, host_data in nm_result.get("hosts", {}).items():
            for proto, ports in host_data.get("protocols", {}).items():
                for port_str, port_info in ports.items():
                    port = int(port_str)
                    if port_info.get("state") == "open":
                        f = self._port_to_finding(host, port, proto, port_info, source_tool)
                        f["_host_ip"] = host
                        findings.append(f)

                    for script_name, script_output in port_info.get("script", {}).items():
                        script_finding = self._script_to_finding(host, port, script_name, script_output, source_tool)
                        if script_finding:
                            script_finding["_host_ip"] = host
                            findings.append(script_finding)

            for osmatch in host_data.get("osmatch", []):
                f = self._os_to_finding(host, osmatch, source_tool)
                f["_host_ip"] = host
                findings.append(f)

        return findings

    def _port_to_finding(self, host: str, port: int, proto: str, info: dict, source_tool: str) -> dict:
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

        severity = "low" if port > 1024 else "info"
        return {
            "title": f"Open port {port}/{proto} — {service} on {host}",
            "description": f"Service {service_str} detected on port {port}",
            "severity": severity,
            "category": "exposure",
            "source_check": f"port_{port}",
            "evidence": f"Port {port}/{proto}: {service_str} (state: open)",
        }

    def _script_to_finding(self, host: str, port: int, script_name: str, output: str, source_tool: str) -> dict | None:
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

    def _os_to_finding(self, host: str, osmatch: dict, source_tool: str) -> dict:
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

    @staticmethod
    def _build_exposure_profile(host_data: dict) -> dict:
        """Build exposure dict from open ports for VulnScanService compatibility."""
        exposure = {}
        for proto, ports in host_data.get("protocols", {}).items():
            for port_str, port_info in ports.items():
                if port_info.get("state") != "open":
                    continue
                port = int(port_str)
                service = port_info.get("name", "")

                if port in (80, 8080, 8000):
                    exposure["admin_ui"] = True
                    exposure["http_exposed"] = True
                if port in (443, 8443):
                    exposure["https_exposed"] = True
                    exposure["admin_ui"] = True
                if port == 22:
                    exposure["ssh_exposed"] = True
                if port == 23:
                    exposure["telnet_exposed"] = True
                if port == 21:
                    exposure["ftp_exposed"] = True
                if port == 445 or port == 139:
                    exposure["smb_exposed"] = True
                if port == 3389:
                    exposure["rdp_exposed"] = True
                if port == 5900:
                    exposure["vnc_exposed"] = True
                if port in (3306, 5432, 1433, 6379, 27017):
                    exposure["db_exposed"] = True
                if port == 161:
                    exposure["snmp_exposed"] = True
                if port == 53:
                    exposure["dns_exposed"] = True
                if port == 389 or port == 636:
                    exposure["ldap_exposed"] = True
                if "upnp" in service.lower() or port == 1900:
                    exposure["upnp_enabled"] = True

        return exposure

    async def auto_import_hosts(self, scan_result: dict, run_id: str | None = None) -> dict:
        """Import discovered hosts as assets. Upsert by IP address."""
        imported = 0
        updated = 0
        asset_ids = []

        for ip, host_data in scan_result.get("hosts", {}).items():
            if host_data.get("state") != "up":
                continue

            result = await self.db.execute(select(Asset).where(Asset.ip_address == ip))
            asset = result.scalar_one_or_none()

            exposure = self._build_exposure_profile(host_data)
            hostnames = host_data.get("hostnames", [])
            os_matches = host_data.get("osmatch", [])
            os_guess = os_matches[0]["name"] if os_matches else None

            if asset:
                # Update existing asset
                if exposure:
                    existing_exposure = asset.exposure or {}
                    existing_exposure.update(exposure)
                    asset.exposure = existing_exposure
                if os_guess and not asset.os_guess:
                    asset.os_guess = os_guess
                if hostnames and not asset.hostname:
                    asset.hostname = hostnames[0]
                asset.last_seen = datetime.utcnow()
                updated += 1
                asset_ids.append(asset.id)
            else:
                # Create new asset
                import uuid
                new_asset = Asset(
                    id=str(uuid.uuid4()),
                    ip_address=ip,
                    hostname=hostnames[0] if hostnames else None,
                    os_guess=os_guess,
                    asset_type="unknown",
                    zone="lan",
                    criticality="medium",
                    exposure=exposure if exposure else None,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                )
                self.db.add(new_asset)
                imported += 1
                asset_ids.append(new_asset.id)

        await self.db.flush()

        if run_id:
            await manager.broadcast(run_id, {
                "type": "nmap_output",
                "line": f"Asset import: {imported} new, {updated} updated",
            })

        return {"imported": imported, "updated": updated, "asset_ids": asset_ids}

    async def execute_custom_scan(
        self, target: str, nmap_args: str, run_id: str | None = None, timeout: int = 600
    ) -> dict:
        """Execute a custom nmap scan, store findings and artifacts."""
        # Validate scope
        if not self.validate_scope(target):
            return {"status": "error", "error": f"Target {target} is outside allowed scope (RFC 1918 only)"}

        # Validate args
        valid, msg = self.validate_nmap_args(nmap_args)
        if not valid:
            return {"status": "error", "error": f"Invalid nmap arguments: {msg}"}

        await self.audit_trail.log(
            event_type="action", entity_type="nmap_scan",
            entity_id=target, actor="user",
            action="nmap_custom_scan",
            run_id=run_id,
            new_value={"target": target, "nmap_args": nmap_args},
        )

        # Run nmap
        scan_result = await self._run_nmap_with_streaming(target, nmap_args, run_id, timeout)

        # Import hosts
        import_result = await self.auto_import_hosts(scan_result, run_id)

        # Parse findings
        raw_findings = self._parse_results(scan_result, target)

        # Store findings per asset
        created = 0
        findings_list = []
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
                    "source_tool": "nmap_custom",
                    "source_check": raw.get("source_check", "custom"),
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

        # Store artifact
        await self.artifact_store.store(
            content=json.dumps({"scan_results": scan_result, "findings": findings_list}, indent=2, default=str),
            artifact_type="raw_output",
            tool_name="nmap_custom",
            target=target,
            run_id=run_id,
            command=f"nmap {nmap_args} {target}",
            parameters={"nmap_args": nmap_args, "target": target},
        )

        await self.db.commit()

        return {
            "status": "completed",
            "target": target,
            "nmap_args": nmap_args,
            "command_line": scan_result.get("command_line", f"nmap {nmap_args} {target}"),
            "scan_result": scan_result,
            "import_result": import_result,
            "findings": findings_list,
            "findings_created": created,
            "total_findings": len(findings_list),
        }

    async def run_full_pipeline(
        self, target: str, nmap_args: str, run_id: str | None = None, timeout: int = 600
    ) -> dict:
        """Run full pipeline: nmap → import → findings → vuln → threat → MITRE → risk."""
        pipeline_result = {
            "steps": {},
            "status": "running",
        }

        async def broadcast_step(step: str, status: str, detail: str = ""):
            if run_id:
                await manager.broadcast(run_id, {
                    "type": "pipeline_step",
                    "step": step,
                    "status": status,
                    "detail": detail,
                })

        try:
            # Step 1: Nmap Scan
            await broadcast_step("nmap_scan", "running", "Starting nmap scan...")
            scan_result = await self._run_nmap_with_streaming(target, nmap_args, run_id, timeout)
            host_count = len(scan_result.get("hosts", {}))
            await broadcast_step("nmap_scan", "completed", f"{host_count} host(s) discovered")
            pipeline_result["steps"]["nmap_scan"] = {"hosts": host_count}

            # Step 2: Asset Import
            await broadcast_step("asset_import", "running", "Importing hosts as assets...")
            import_result = await self.auto_import_hosts(scan_result, run_id)
            await broadcast_step("asset_import", "completed",
                                 f"{import_result['imported']} imported, {import_result['updated']} updated")
            pipeline_result["steps"]["asset_import"] = import_result

            # Step 3: Store Findings
            await broadcast_step("store_findings", "running", "Creating findings from scan results...")
            raw_findings = self._parse_results(scan_result, target)

            created = 0
            findings_list = []
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
                        "source_tool": "nmap_custom",
                        "source_check": raw.get("source_check", "custom"),
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

            # Store artifact
            await self.artifact_store.store(
                content=json.dumps({"scan_results": scan_result, "findings": findings_list}, indent=2, default=str),
                artifact_type="raw_output",
                tool_name="nmap_custom",
                target=target,
                run_id=run_id,
                command=f"nmap {nmap_args} {target}",
                parameters={"nmap_args": nmap_args, "target": target},
            )

            await self.db.commit()
            await broadcast_step("store_findings", "completed", f"{created} new findings, {len(findings_list)} total")
            pipeline_result["steps"]["store_findings"] = {
                "findings_created": created,
                "total_findings": len(findings_list),
            }

            # Step 4: Vuln Assessment
            await broadcast_step("vuln_assessment", "running", "Running vulnerability assessment...")
            try:
                from app.services.vuln_scan_service import VulnScanService
                vuln_service = VulnScanService(self.db)
                vuln_result = await vuln_service.run_vuln_scan(run_id=run_id)
                await self.db.commit()
                vuln_detail = f"{vuln_result.get('total_new_findings', 0)} new vuln findings"
                await broadcast_step("vuln_assessment", "completed", vuln_detail)
                pipeline_result["steps"]["vuln_assessment"] = {
                    "new_findings": vuln_result.get("total_new_findings", 0),
                    "total_findings": vuln_result.get("total_findings", 0),
                }
            except Exception as e:
                logger.error("Vuln assessment failed", error=str(e))
                await broadcast_step("vuln_assessment", "completed", f"Skipped: {str(e)[:100]}")
                pipeline_result["steps"]["vuln_assessment"] = {"skipped": True, "error": str(e)[:200]}

            # Step 5: Threat Modeling
            await broadcast_step("threat_modeling", "running", "Running threat modeling...")
            try:
                from app.services.threat_service import ThreatService
                threat_service = ThreatService(self.db)
                threat_result = await threat_service.run_threat_modeling(run_id=run_id)
                await self.db.commit()
                threat_detail = f"{threat_result.get('threats_created', 0)} threats generated"
                await broadcast_step("threat_modeling", "completed", threat_detail)
                pipeline_result["steps"]["threat_modeling"] = {
                    "threats_created": threat_result.get("threats_created", 0),
                    "total_threats": threat_result.get("total_threats", 0),
                }
            except Exception as e:
                logger.error("Threat modeling failed", error=str(e))
                await broadcast_step("threat_modeling", "completed", f"Skipped: {str(e)[:100]}")
                pipeline_result["steps"]["threat_modeling"] = {"skipped": True, "error": str(e)[:200]}

            # Step 6: MITRE Mapping
            await broadcast_step("mitre_mapping", "running", "Running MITRE ATT&CK mapping...")
            try:
                from app.services.mitre_service import MitreService
                mitre_service = MitreService(self.db)
                mitre_result = await mitre_service.run_mapping(run_id=run_id)
                await self.db.commit()
                mitre_detail = f"{mitre_result.get('mappings_created', 0)} mappings created"
                await broadcast_step("mitre_mapping", "completed", mitre_detail)
                pipeline_result["steps"]["mitre_mapping"] = {
                    "mappings_created": mitre_result.get("mappings_created", 0),
                }
            except Exception as e:
                logger.error("MITRE mapping failed", error=str(e))
                await broadcast_step("mitre_mapping", "completed", f"Skipped: {str(e)[:100]}")
                pipeline_result["steps"]["mitre_mapping"] = {"skipped": True, "error": str(e)[:200]}

            # Step 7: Risk Analysis
            await broadcast_step("risk_analysis", "running", "Running risk analysis...")
            try:
                from app.services.risk_analysis_service import RiskAnalysisService
                risk_service = RiskAnalysisService(self.db)
                risk_result = await risk_service.run_risk_analysis(run_id=run_id)
                await self.db.commit()
                risk_detail = f"{risk_result.get('risks_created', 0)} risks identified"
                await broadcast_step("risk_analysis", "completed", risk_detail)
                pipeline_result["steps"]["risk_analysis"] = {
                    "risks_created": risk_result.get("risks_created", 0),
                    "risks_updated": risk_result.get("risks_updated", 0),
                }
            except Exception as e:
                logger.error("Risk analysis failed", error=str(e))
                await broadcast_step("risk_analysis", "completed", f"Skipped: {str(e)[:100]}")
                pipeline_result["steps"]["risk_analysis"] = {"skipped": True, "error": str(e)[:200]}

            # Pipeline complete
            pipeline_result["status"] = "completed"
            pipeline_result["scan_result"] = scan_result
            pipeline_result["findings"] = findings_list
            pipeline_result["findings_created"] = created
            pipeline_result["total_findings"] = len(findings_list)
            pipeline_result["import_result"] = import_result

            if run_id:
                await manager.broadcast(run_id, {
                    "type": "pipeline_complete",
                    "result": {
                        "steps": pipeline_result["steps"],
                        "findings_created": created,
                        "total_findings": len(findings_list),
                        "assets_imported": import_result["imported"],
                        "assets_updated": import_result["updated"],
                    },
                })

            return pipeline_result

        except Exception as e:
            logger.error("Pipeline failed", error=str(e), run_id=run_id)
            pipeline_result["status"] = "error"
            pipeline_result["error"] = str(e)
            if run_id:
                await manager.broadcast(run_id, {
                    "type": "pipeline_error",
                    "error": str(e),
                })
            raise
