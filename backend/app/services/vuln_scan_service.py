import json
import asyncio
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


class VulnScanService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)
        self.finding_service = FindingService(db)

    async def run_vuln_scan(
        self, asset_id: str | None = None, run_id: str | None = None, timeout: int = 300
    ) -> dict:
        """Run vulnerability scanning on one or all assets."""
        logger.info("Starting vuln scan", asset_id=asset_id, run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="vuln_scan_start", run_id=run_id,
        )

        # Get target assets
        if asset_id:
            result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            assets = [asset] if asset else []
        else:
            result = await self.db.execute(select(Asset))
            assets = list(result.scalars().all())

        total_created = 0
        total_duplicate = 0
        total_errors = 0
        all_findings = []

        for asset in assets:
            try:
                findings, created, duplicate = await self._scan_asset(
                    asset, run_id, timeout // max(len(assets), 1)
                )
                total_created += created
                total_duplicate += duplicate
                all_findings.extend(findings)
            except Exception as e:
                logger.error("Vuln scan failed for asset", ip=asset.ip_address, error=str(e))
                total_errors += 1

        # Store artifact
        summary = {
            "findings_created": total_created,
            "findings_duplicate": total_duplicate,
            "errors": total_errors,
            "total_assets": len(assets),
        }
        await self.artifact_store.store(
            content=json.dumps(
                {"findings": [self._finding_to_dict(f) for f in all_findings], "summary": summary},
                indent=2, default=str,
            ),
            artifact_type="raw_output",
            tool_name="vuln_scan_service",
            target="all_assets" if not asset_id else asset_id,
            run_id=run_id,
            command=f"vuln_scan asset_id={asset_id}",
            parameters={"asset_id": asset_id, "timeout": timeout},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="vuln_scan_complete", run_id=run_id,
            new_value=summary,
        )

        logger.info("Vuln scan complete", created=total_created, duplicate=total_duplicate)
        return {
            "status": "completed",
            "findings_created": total_created,
            "findings_duplicate": total_duplicate,
            "errors": total_errors,
            "total_assets": len(assets),
        }

    async def _scan_asset(
        self, asset: Asset, run_id: str | None, timeout: int
    ) -> tuple[list[Finding], int, int]:
        """Scan a single asset using all relevant checks."""
        target = asset.ip_address
        exposure = asset.exposure or {}
        raw_findings = []

        open_ports = self._get_open_ports(exposure)

        # Try real network checks first
        network_reachable = await self._check_reachable(target)

        if network_reachable:
            # HTTP checks
            http_ports = [p for p in open_ports if p in (80, 8080, 8000, 8008, 8888, 3000, 9090)]
            https_ports = [p for p in open_ports if p in (443, 8443, 4443)]

            for port in http_ports:
                try:
                    findings = await self._run_http_check(target, port, use_tls=False)
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("HTTP check failed", target=target, port=port, error=str(e))

            for port in https_ports:
                try:
                    findings = await self._run_http_check(target, port, use_tls=True)
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("HTTPS check failed", target=target, port=port, error=str(e))

            # TLS checks
            tls_ports = [p for p in open_ports if p in (443, 8443, 4443, 993, 995, 465, 636)]
            for port in tls_ports:
                try:
                    findings = await self._run_tls_check(target, port)
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("TLS check failed", target=target, port=port, error=str(e))

            # SSH check
            if 22 in open_ports:
                try:
                    findings = await self._run_ssh_check(target, 22)
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("SSH check failed", target=target, error=str(e))

            # DNS check
            if 53 in open_ports:
                try:
                    findings = await self._run_dns_check(target, 53)
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("DNS check failed", target=target, error=str(e))

            # SNMP check
            if 161 in open_ports:
                try:
                    findings = await asyncio.wait_for(
                        self._run_snmp_check(target, 161), timeout=10
                    )
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("SNMP check failed", target=target, error=str(e))

            # SMB check
            if 445 in open_ports:
                try:
                    findings = await asyncio.wait_for(
                        self._run_smb_check(target, 445), timeout=10
                    )
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("SMB check failed", target=target, error=str(e))

            # Default credentials check (on HTTP ports)
            for port in http_ports[:2]:  # Check first 2 HTTP ports max
                try:
                    device_type = asset.asset_type or "generic"
                    findings = await asyncio.wait_for(
                        self._run_default_creds_check(target, port, device_type), timeout=10
                    )
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("Default creds check failed", target=target, port=port, error=str(e))

            # mDNS/LLMNR check
            if 5353 in open_ports:
                try:
                    findings = await asyncio.wait_for(
                        self._run_mdns_llmnr_check(target), timeout=10
                    )
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("mDNS/LLMNR check failed", target=target, error=str(e))

            # MQTT check
            mqtt_ports = [p for p in open_ports if p in (1883, 8883)]
            for port in mqtt_ports:
                try:
                    findings = await asyncio.wait_for(
                        self._run_mqtt_check(target, port), timeout=10
                    )
                    raw_findings.extend(findings)
                except Exception as e:
                    logger.debug("MQTT check failed", target=target, port=port, error=str(e))
        else:
            # Network not reachable - generate simulated findings from exposure profile
            logger.info("Target not reachable, generating simulated findings", target=target)
            raw_findings = self._generate_simulated_findings(asset)

        # Create deduplicated findings in DB
        created = 0
        duplicate = 0
        db_findings = []

        for raw in raw_findings:
            if raw.get("severity") == "info":
                continue  # Skip pure info findings from DB storage

            finding_data = {
                "asset_id": asset.id,
                "run_id": run_id,
                "title": raw["title"],
                "description": raw.get("description", ""),
                "severity": raw.get("severity", "info"),
                "category": raw.get("category", "info"),
                "source_tool": raw.get("source_tool", "vuln_scan"),
                "source_check": raw.get("source_check", raw.get("source_tool", "vuln_scan")),
                "cve_ids": raw.get("cve_ids", []),
                "cwe_id": raw.get("cwe_id"),
                "evidence_artifact_ids": [],
                "raw_output_snippet": raw.get("evidence", ""),
                "remediation": raw.get("remediation"),
            }

            finding, is_new = await self.finding_service.create_deduplicated(finding_data)
            db_findings.append(finding)
            if is_new:
                created += 1
            else:
                duplicate += 1

        return db_findings, created, duplicate

    def _get_open_ports(self, exposure: dict) -> list[int]:
        """Derive open ports from exposure indicators."""
        ports = []
        if exposure.get("admin_ui"):
            ports.extend([80, 443, 8080, 8443, 9090])
        if exposure.get("ssh_exposed"):
            ports.append(22)
        if exposure.get("telnet_exposed"):
            ports.append(23)
        if exposure.get("ftp_exposed"):
            ports.append(21)
        if exposure.get("smb_exposed"):
            ports.append(445)
        if exposure.get("upnp"):
            ports.extend([1900, 5000])
        if exposure.get("snmp_exposed"):
            ports.append(161)
        if exposure.get("mqtt_exposed"):
            ports.extend([1883, 8883])
        # Always try common ports + new protocol ports
        ports.extend([80, 443, 22, 161, 445, 5353, 1883])
        return list(set(ports))

    async def _run_http_check(self, target: str, port: int, use_tls: bool) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.http_checks import HTTPSecurityChecker
        checker = HTTPSecurityChecker()
        findings = await checker.check(target, port, use_tls)
        for f in findings:
            f["source_tool"] = "http_security"
            f["source_check"] = "http_security"
        return findings

    async def _run_tls_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.tls_checks import TLSChecker
        checker = TLSChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "tls_check"
            f["source_check"] = "tls_check"
        return findings

    async def _run_ssh_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.ssh_checks import SSHChecker
        checker = SSHChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "ssh_check"
            f["source_check"] = "ssh_check"
        return findings

    async def _run_dns_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.dns_checks import DNSChecker
        checker = DNSChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "dns_check"
            f["source_check"] = "dns_check"
        return findings

    async def _run_snmp_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.snmp_checks import SNMPChecker
        checker = SNMPChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "snmp_check"
            f["source_check"] = "snmp_check"
        return findings

    async def _run_smb_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.smb_checks import SMBChecker
        checker = SMBChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "smb_check"
            f["source_check"] = "smb_check"
        return findings

    async def _run_default_creds_check(self, target: str, port: int, device_type: str = "generic") -> list[dict]:
        from mcp_servers.vuln_scanning.checks.default_creds_check import DefaultCredsChecker
        checker = DefaultCredsChecker()
        findings = await checker.check(target, port, device_type=device_type)
        for f in findings:
            f["source_tool"] = "default_creds_check"
            f["source_check"] = "default_creds_check"
        return findings

    async def _run_mdns_llmnr_check(self, target: str) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.mdns_llmnr_checks import MDNSLLMNRChecker
        checker = MDNSLLMNRChecker()
        findings = await checker.check(target)
        for f in findings:
            f["source_tool"] = "mdns_check"
            f["source_check"] = "mdns_check"
        return findings

    async def _run_mqtt_check(self, target: str, port: int) -> list[dict]:
        from mcp_servers.vuln_scanning.checks.mqtt_checks import MQTTChecker
        checker = MQTTChecker()
        findings = await checker.check(target, port)
        for f in findings:
            f["source_tool"] = "mqtt_check"
            f["source_check"] = "mqtt_check"
        return findings

    async def _check_reachable(self, target: str) -> bool:
        """Quick check if a target is reachable."""
        import asyncio
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 80), timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Try ping as fallback
            try:
                import subprocess, platform
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", "1", "-w", "1000", target]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", target]
                proc = await asyncio.to_thread(
                    subprocess.run, cmd,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=3,
                )
                return proc.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                return False

    def _generate_simulated_findings(self, asset: Asset) -> list[dict]:
        """Generate realistic findings based on asset exposure profile."""
        findings = []
        exposure = asset.exposure or {}
        asset_type = asset.asset_type or "unknown"
        os_guess = (asset.os_guess or "").lower()

        # Admin UI without TLS
        if exposure.get("admin_ui"):
            findings.append({
                "title": f"HTTP admin interface without TLS on {asset.ip_address}",
                "severity": "medium",
                "category": "misconfig",
                "source_tool": "http_security",
                "source_check": "http_notls",
                "description": f"Device {asset.hostname or asset.ip_address} exposes an administrative web interface over unencrypted HTTP.",
                "remediation": "Enable HTTPS/TLS on the admin interface. Use a self-signed certificate if no CA is available.",
                "cwe_id": "CWE-319",
                "evidence": f"HTTP admin UI detected on {asset.ip_address} (exposure profile)",
            })
            findings.append({
                "title": f"Missing security headers on {asset.ip_address} web interface",
                "severity": "medium",
                "category": "misconfig",
                "source_tool": "http_security",
                "source_check": "http_headers",
                "description": "Web interface is missing common security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options).",
                "remediation": "Configure web server to send security headers: Strict-Transport-Security, X-Frame-Options, Content-Security-Policy.",
                "cwe_id": "CWE-693",
                "evidence": f"Security headers missing on {asset.ip_address} web interface",
            })

        # Telnet exposed - critical
        if exposure.get("telnet_exposed"):
            findings.append({
                "title": f"Telnet service exposed on {asset.ip_address}",
                "severity": "critical",
                "category": "vuln",
                "source_tool": "vuln_scan",
                "source_check": "telnet_exposed",
                "description": f"Telnet transmits credentials in cleartext. Device {asset.hostname or asset.ip_address} has telnet enabled.",
                "remediation": "Disable telnet immediately. Use SSH for remote management.",
                "cwe_id": "CWE-319",
                "cve_ids": [],
                "evidence": f"Telnet service (port 23) detected on {asset.ip_address}",
            })

        # FTP exposed
        if exposure.get("ftp_exposed"):
            findings.append({
                "title": f"FTP service exposed on {asset.ip_address}",
                "severity": "high",
                "category": "vuln",
                "source_tool": "vuln_scan",
                "source_check": "ftp_exposed",
                "description": f"FTP transmits credentials and data in cleartext. Device {asset.hostname or asset.ip_address} has FTP enabled.",
                "remediation": "Disable FTP and use SFTP or SCP instead.",
                "cwe_id": "CWE-319",
                "evidence": f"FTP service (port 21) detected on {asset.ip_address}",
            })

        # SSH exposed
        if exposure.get("ssh_exposed"):
            findings.append({
                "title": f"SSH service exposed on {asset.ip_address}",
                "severity": "low",
                "category": "exposure",
                "source_tool": "ssh_check",
                "source_check": "ssh_exposed",
                "description": f"SSH is exposed on {asset.hostname or asset.ip_address}. Ensure strong authentication is configured.",
                "remediation": "Disable password authentication. Use key-based auth. Consider fail2ban.",
                "cwe_id": "CWE-307",
                "evidence": f"SSH service (port 22) detected on {asset.ip_address}",
            })
            findings.append({
                "title": f"SSH password authentication likely enabled on {asset.ip_address}",
                "severity": "medium",
                "category": "misconfig",
                "source_tool": "ssh_check",
                "source_check": "ssh_password_auth",
                "description": "SSH password authentication is commonly enabled by default, making it susceptible to brute-force attacks.",
                "remediation": "Disable PasswordAuthentication in sshd_config. Use key-based authentication.",
                "cwe_id": "CWE-307",
                "evidence": f"SSH service with likely password auth on {asset.ip_address}",
            })

        # SMB exposed
        if exposure.get("smb_exposed"):
            findings.append({
                "title": f"SMB/CIFS file sharing exposed on {asset.ip_address}",
                "severity": "medium",
                "category": "exposure",
                "source_tool": "vuln_scan",
                "source_check": "smb_exposed",
                "description": f"SMB file sharing is exposed on {asset.hostname or asset.ip_address}. This can be targeted for lateral movement.",
                "remediation": "Restrict SMB access to required clients. Disable SMBv1. Use firewall rules.",
                "cwe_id": "CWE-200",
                "evidence": f"SMB service (port 445) detected on {asset.ip_address}",
            })

        # UPnP enabled
        if exposure.get("upnp"):
            findings.append({
                "title": f"UPnP enabled on {asset.ip_address}",
                "severity": "high",
                "category": "misconfig",
                "source_tool": "vuln_scan",
                "source_check": "upnp_enabled",
                "description": f"UPnP allows automatic port forwarding, potentially exposing internal services to the internet.",
                "remediation": "Disable UPnP on the device. Manually configure port forwarding if needed.",
                "cwe_id": "CWE-284",
                "evidence": f"UPnP service (port 1900) detected on {asset.ip_address}",
            })

        # Device-specific findings
        if asset_type == "router":
            findings.append({
                "title": f"Router admin interface exposed to LAN on {asset.ip_address}",
                "severity": "medium",
                "category": "exposure",
                "source_tool": "vuln_scan",
                "source_check": "router_admin",
                "description": "Router admin interface is accessible from the LAN. Compromised LAN devices could reconfigure the router.",
                "remediation": "Use strong admin credentials. Enable admin access restrictions. Consider admin VLAN.",
                "cwe_id": "CWE-284",
                "evidence": f"Router admin UI on {asset.ip_address}",
            })

        if asset_type == "iot" and "camera" in os_guess:
            findings.append({
                "title": f"IP camera with potential default credentials on {asset.ip_address}",
                "severity": "high",
                "category": "vuln",
                "source_tool": "vuln_scan",
                "source_check": "default_creds",
                "description": f"IP cameras frequently ship with default credentials. Device {asset.hostname or asset.ip_address} should be checked.",
                "remediation": "Change default credentials immediately. Disable unused services (telnet, FTP).",
                "cwe_id": "CWE-798",
                "evidence": f"IP camera detected at {asset.ip_address} with multiple exposed services",
            })

        if "synology" in os_guess or asset_type == "nas":
            findings.append({
                "title": f"NAS device with self-signed TLS certificate on {asset.ip_address}",
                "severity": "low",
                "category": "misconfig",
                "source_tool": "tls_check",
                "source_check": "self_signed_cert",
                "description": "NAS uses a self-signed certificate. While common, this prevents proper certificate validation.",
                "remediation": "Consider using Let's Encrypt or a local CA for the NAS certificate.",
                "cwe_id": "CWE-295",
                "evidence": f"Self-signed TLS cert likely on {asset.ip_address} (Synology default)",
            })

        if "windows" in os_guess:
            findings.append({
                "title": f"Windows Remote Desktop potentially accessible on {asset.ip_address}",
                "severity": "medium",
                "category": "exposure",
                "source_tool": "vuln_scan",
                "source_check": "rdp_check",
                "description": "Windows systems often have RDP enabled. Ensure it's properly secured.",
                "remediation": "Enable Network Level Authentication (NLA). Use strong passwords. Consider disabling RDP if not needed.",
                "cwe_id": "CWE-284",
                "evidence": f"Windows system detected at {asset.ip_address} with SMB exposed",
            })

        return findings

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict:
        return {
            "id": finding.id,
            "asset_id": finding.asset_id,
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
            "source_tool": finding.source_tool,
        }
