import json
import asyncio
import ipaddress
import re
import subprocess
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.artifact import Artifact
from app.models.audit_event import AuditEvent
from app.evidence.artifact_store import ArtifactStore
from app.evidence.audit_trail import AuditTrail
from app.services.asset_service import AssetService
from app.mcp_client.client import MCPClient
import structlog

logger = structlog.get_logger()

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


class DiscoveryService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.asset_service = AssetService(db)
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)

    @staticmethod
    def _validate_scope(target: str) -> bool:
        """Validate target is in RFC 1918 private range."""
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
    def _build_exposure_from_ports(ports: list[dict]) -> dict:
        """Build exposure profile from a list of port dicts."""
        exposure = {}
        for p in ports:
            port = p["port"]
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
        return exposure

    @staticmethod
    def _parse_grepable_output(output: str) -> list[dict]:
        """Parse nmap grepable (-oG) output into host dicts with ports."""
        hosts = []
        for line in output.splitlines():
            if not line.startswith("Host:"):
                continue
            if "Ports:" not in line:
                continue

            # Extract IP and optional hostname
            # Format: Host: 192.168.178.1 (router.local)\tPorts: ...
            # or:     Host: 192.168.178.1 ()\tPorts: ...
            header_part, _, ports_part = line.partition("Ports:")
            ip_match = re.match(r"Host:\s+([\d.]+)\s+\(([^)]*)\)", header_part)
            if not ip_match:
                continue

            ip = ip_match.group(1)
            hostname = ip_match.group(2).strip() or None

            # Parse ports: 80/open/tcp//http///, 443/open/tcp//https///
            ports = []
            port_entries = ports_part.strip().split(",")
            for entry in port_entries:
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("/")
                if len(parts) < 5:
                    continue
                try:
                    port_num = int(parts[0])
                except ValueError:
                    continue
                state = parts[1]
                if state != "open":
                    continue
                proto = parts[2]
                service = parts[4] if len(parts) > 4 else ""
                ports.append({"port": port_num, "proto": proto, "service": service})

            if ports:
                hosts.append({"ip": ip, "hostname": hostname, "ports": ports})
        return hosts

    async def run_nmap_discovery(self, network: str, timeout: int = 120) -> dict:
        """Run nmap -sS --open -oG - <network> and return hosts with open ports."""
        logger.info("Starting nmap discovery", network=network, timeout=timeout)

        # Validate scope
        if not self._validate_scope(network):
            raise ValueError(f"Target {network} is not in RFC 1918 private range")

        # Sanitize: reject shell metacharacters
        if re.search(r"[;&|`$()>\"]", network):
            raise ValueError("Invalid characters in network target")

        # Run nmap subprocess (use subprocess.run in thread — asyncio subprocess
        # is not supported on Windows SelectorEventLoop used by uvicorn)
        cmd = ["nmap", "-sS", "--open", "-T4", "--host-timeout", "15s", "-oG", "-", network]
        try:
            proc = await asyncio.to_thread(
                subprocess.run, cmd,
                capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("nmap discovery timed out", network=network, timeout=timeout)
            return {"status": "timeout", "hosts": [], "assets_created": 0, "assets_updated": 0}

        raw_output = proc.stdout.decode("utf-8", errors="replace")
        stderr_text = proc.stderr.decode("utf-8", errors="replace")

        if proc.returncode != 0 and not raw_output.strip():
            logger.error("nmap failed", returncode=proc.returncode, stderr=stderr_text)
            raise RuntimeError(f"nmap exited with code {proc.returncode}: {stderr_text[:500]}")

        # Parse grepable output
        hosts = self._parse_grepable_output(raw_output)

        # Upsert assets
        created = 0
        updated = 0
        for host in hosts:
            exposure = self._build_exposure_from_ports(host["ports"])
            asset_data = {
                "ip_address": host["ip"],
                "hostname": host["hostname"],
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "exposure": exposure,
            }

            existing = await self.asset_service.find_by_ip(host["ip"])
            if existing:
                updated += 1
            else:
                created += 1
            await self.asset_service.upsert_from_scan(asset_data)

        # Store artifact
        await self.artifact_store.store(
            content=raw_output,
            artifact_type="raw_output",
            tool_name="nmap_discovery",
            target=network,
            command=" ".join(cmd),
            parameters={"network": network, "timeout": timeout},
        )

        # Audit trail
        await self.audit_trail.log(
            event_type="step_complete",
            entity_type="discovery",
            entity_id="manual",
            actor="system",
            action="nmap_discovery_complete",
            new_value={
                "hosts_found": len(hosts),
                "assets_created": created,
                "assets_updated": updated,
            },
        )

        await self.db.commit()

        logger.info("nmap discovery complete", hosts=len(hosts), created=created, updated=updated)
        return {
            "status": "completed",
            "hosts": hosts,
            "assets_created": created,
            "assets_updated": updated,
        }

    async def run_discovery(self, subnet: str, run_id: str | None = None, timeout: int = 60) -> dict:
        """Run full network discovery and create/update assets."""
        logger.info("Starting discovery", subnet=subnet, run_id=run_id)

        # Log start event
        await self.audit_trail.log(
            event_type="step_start",
            entity_type="run",
            entity_id=run_id or "manual",
            actor="system",
            action="discovery_start",
            run_id=run_id,
            new_value={"subnet": subnet, "timeout": timeout},
        )

        discovered_hosts = []
        errors = []

        # Try nmap-based discovery first
        try:
            discovered_hosts = await self._nmap_discovery(subnet, timeout)
        except Exception as e:
            logger.warning("nmap discovery failed", error=str(e))
            errors.append(f"nmap: {str(e)}")

        # Fallback to native ping sweep
        if not discovered_hosts:
            try:
                discovered_hosts = await self._ping_discovery(subnet, timeout)
            except Exception as e:
                logger.warning("ping discovery failed", error=str(e))
                errors.append(f"ping: {str(e)}")

        # Try passive discovery methods (non-blocking)
        mdns_results = []
        ssdp_results = []
        try:
            mdns_results, ssdp_results = await asyncio.gather(
                self._mdns_discovery(),
                self._ssdp_discovery(),
                return_exceptions=True,
            )
            if isinstance(mdns_results, Exception):
                errors.append(f"mdns: {str(mdns_results)}")
                mdns_results = []
            if isinstance(ssdp_results, Exception):
                errors.append(f"ssdp: {str(ssdp_results)}")
                ssdp_results = []
        except Exception as e:
            errors.append(f"passive: {str(e)}")

        # If no real hosts found, seed demo network for demonstration
        if not discovered_hosts and not mdns_results and not ssdp_results:
            logger.info("No real hosts found, seeding demo network")
            discovered_hosts = self._get_demo_network()
            errors.append("demo_mode: No live hosts found on network, using simulated home network")

        # Create/update assets from discovered hosts
        created = 0
        updated = 0
        assets = []

        # Batch-load existing assets by IP to avoid N+1 queries
        all_ips = [
            host.get("ip_address") or host.get("ip", "")
            for host in discovered_hosts
            if host.get("ip_address") or host.get("ip", "")
        ]
        existing_by_ip = {}
        if all_ips:
            from app.models.asset import Asset as AssetModel
            result = await self.db.execute(
                select(AssetModel).where(AssetModel.ip_address.in_(all_ips))
            )
            for a in result.scalars().all():
                existing_by_ip[a.ip_address] = a

        for host in discovered_hosts:
            asset_data = {
                "ip_address": host.get("ip_address") or host.get("ip", ""),
                "mac_address": host.get("mac_address"),
                "hostname": host.get("hostname"),
                "vendor": host.get("vendor"),
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
            }
            # Carry over enriched fields from demo network
            for field in ("asset_type", "zone", "criticality", "os_guess", "exposure", "data_types"):
                if host.get(field) is not None:
                    asset_data[field] = host[field]

            if not asset_data["ip_address"]:
                continue

            is_existing = asset_data["ip_address"] in existing_by_ip
            asset = await self.asset_service.upsert_from_scan(asset_data)
            if is_existing:
                updated += 1
            else:
                created += 1
            assets.append(asset)

        # Enrich with mDNS data (batch lookup)
        if isinstance(mdns_results, list):
            mdns_ips = [svc.get("ip") for svc in mdns_results if svc.get("ip")]
            mdns_by_ip = {}
            if mdns_ips:
                from app.models.asset import Asset as AssetModel
                result = await self.db.execute(
                    select(AssetModel).where(AssetModel.ip_address.in_(mdns_ips))
                )
                for a in result.scalars().all():
                    mdns_by_ip[a.ip_address] = a
            for svc in mdns_results:
                ip = svc.get("ip")
                if ip:
                    existing = mdns_by_ip.get(ip)
                    if existing and svc.get("hostname"):
                        if not existing.hostname:
                            existing.hostname = svc["hostname"].rstrip(".")

        # Store artifact
        discovery_data = {
            "hosts": discovered_hosts,
            "mdns_services": mdns_results if isinstance(mdns_results, list) else [],
            "ssdp_devices": ssdp_results if isinstance(ssdp_results, list) else [],
            "summary": {
                "total_discovered": len(discovered_hosts),
                "assets_created": created,
                "assets_updated": updated,
            },
        }

        await self.artifact_store.store(
            content=json.dumps(discovery_data, indent=2, default=str),
            artifact_type="raw_output",
            tool_name="discovery_service",
            target=subnet,
            run_id=run_id,
            command=f"full_discovery subnet={subnet} timeout={timeout}",
            parameters={"subnet": subnet, "timeout": timeout},
        )

        # Log completion
        await self.audit_trail.log(
            event_type="step_complete",
            entity_type="run",
            entity_id=run_id or "manual",
            actor="system",
            action="discovery_complete",
            run_id=run_id,
            new_value=discovery_data["summary"],
        )

        logger.info("Discovery complete", created=created, updated=updated, total=len(discovered_hosts))

        return {
            "status": "completed",
            "hosts_discovered": len(discovered_hosts),
            "assets_created": created,
            "assets_updated": updated,
            "mdns_services": len(mdns_results) if isinstance(mdns_results, list) else 0,
            "ssdp_devices": len(ssdp_results) if isinstance(ssdp_results, list) else 0,
            "errors": errors,
        }

    def _get_demo_network(self) -> list[dict]:
        """Return simulated home network devices for demo/Docker environments."""
        return [
            {
                "ip_address": "192.168.178.1", "hostname": "router.local",
                "vendor": "TP-Link", "mac_address": "B4:E6:2D:AA:BB:01",
                "asset_type": "router", "zone": "lan", "criticality": "critical",
                "os_guess": "Embedded/Router",
                "data_types": ["network_config"],
                "exposure": {"admin_ui": True, "ssh_exposed": False, "telnet_exposed": False,
                             "smb_exposed": False, "upnp": True, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.10", "hostname": "nas.local",
                "vendor": "Synology", "mac_address": "00:11:32:AA:BB:02",
                "asset_type": "nas", "zone": "lan", "criticality": "high",
                "os_guess": "Synology DSM (Linux)",
                "data_types": ["personal", "financial", "backups"],
                "exposure": {"admin_ui": True, "ssh_exposed": True, "telnet_exposed": False,
                             "smb_exposed": True, "upnp": False, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.20", "hostname": "desktop-pc.local",
                "vendor": "Dell", "mac_address": "F8:B1:56:AA:BB:03",
                "asset_type": "workstation", "zone": "lan", "criticality": "high",
                "os_guess": "Windows 11",
                "data_types": ["personal", "credentials"],
                "exposure": {"admin_ui": False, "ssh_exposed": False, "telnet_exposed": False,
                             "smb_exposed": True, "upnp": False, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.30", "hostname": "smart-tv.local",
                "vendor": "Samsung", "mac_address": "54:E1:AD:AA:BB:04",
                "asset_type": "iot", "zone": "iot", "criticality": "low",
                "os_guess": "Tizen (Smart TV)",
                "data_types": [],
                "exposure": {"admin_ui": True, "ssh_exposed": False, "telnet_exposed": False,
                             "smb_exposed": False, "upnp": True, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.40", "hostname": "hue-bridge.local",
                "vendor": "Philips Hue", "mac_address": "00:17:88:AA:BB:05",
                "asset_type": "iot", "zone": "iot", "criticality": "medium",
                "os_guess": "Embedded/IoT Hub",
                "data_types": [],
                "exposure": {"admin_ui": True, "ssh_exposed": False, "telnet_exposed": False,
                             "smb_exposed": False, "upnp": True, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.50", "hostname": "printer.local",
                "vendor": "HP", "mac_address": "3C:97:0E:AA:BB:06",
                "asset_type": "iot", "zone": "lan", "criticality": "low",
                "os_guess": "Embedded/Printer",
                "data_types": [],
                "exposure": {"admin_ui": True, "ssh_exposed": False, "telnet_exposed": False,
                             "smb_exposed": False, "upnp": False, "ftp_exposed": False},
            },
            {
                "ip_address": "192.168.178.60", "hostname": "ipcam-garage.local",
                "vendor": "Hikvision", "mac_address": "AC:CF:5C:AA:BB:07",
                "asset_type": "iot", "zone": "iot", "criticality": "medium",
                "os_guess": "Embedded/IP Camera",
                "data_types": ["video_feed"],
                "exposure": {"admin_ui": True, "ssh_exposed": False, "telnet_exposed": True,
                             "smb_exposed": False, "upnp": True, "ftp_exposed": True},
            },
            {
                "ip_address": "192.168.178.70", "hostname": "pihole.local",
                "vendor": "Raspberry Pi", "mac_address": "B8:27:EB:AA:BB:08",
                "asset_type": "server", "zone": "lan", "criticality": "high",
                "os_guess": "Linux (Raspberry Pi)",
                "data_types": ["dns_logs"],
                "exposure": {"admin_ui": True, "ssh_exposed": True, "telnet_exposed": False,
                             "smb_exposed": False, "upnp": False, "ftp_exposed": False},
            },
        ]

    async def _nmap_discovery(self, subnet: str, timeout: int) -> list[dict]:
        """Discovery using python-nmap."""
        import nmap
        nm = nmap.PortScanner()
        loop = asyncio.get_event_loop()
        # Use a hard overall timeout (half the given timeout) to prevent hanging
        scan_timeout = max(timeout // 2, 15)
        try:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: nm.scan(hosts=subnet, arguments=f"-sn -n --host-timeout {min(timeout, 10)}s --max-retries 1"),
                ),
                timeout=scan_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("nmap discovery timed out", subnet=subnet, timeout=scan_timeout)
            return []

        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = nm[host]["addresses"].get("mac", "")
                vendor_dict = nm[host].get("vendor", {})
                vendor = next(iter(vendor_dict.values()), None) if vendor_dict else None
                hostname = nm[host].hostname() or None

                if not hostname:
                    try:
                        hostname = (await asyncio.wait_for(
                            loop.run_in_executor(
                                None, lambda h=host: __import__("socket").gethostbyaddr(h)[0]
                            ),
                            timeout=2,
                        ))
                    except (asyncio.TimeoutError, Exception):
                        pass

                results.append({
                    "ip_address": host,
                    "mac_address": mac or None,
                    "hostname": hostname,
                    "vendor": vendor,
                })

        return results

    async def _ping_discovery(self, subnet: str, timeout: int) -> list[dict]:
        """Discovery using native ping sweep."""
        import ipaddress
        import platform

        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 256:
            network = ipaddress.ip_network(f"{network.network_address}/24", strict=False)

        sem = asyncio.Semaphore(50)
        results: list[dict] = []

        async def ping_host(ip: str):
            async with sem:
                try:
                    if platform.system().lower() == "windows":
                        cmd = ["ping", "-n", "1", "-w", "1000", ip]
                    else:
                        cmd = ["ping", "-c", "1", "-W", "1", ip]
                    proc = await asyncio.to_thread(
                        subprocess.run, cmd,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=3,
                    )
                    if proc.returncode == 0:
                        hostname = None
                        try:
                            hostname = (await asyncio.wait_for(
                                asyncio.get_event_loop().run_in_executor(
                                    None, lambda: __import__("socket").gethostbyaddr(ip)[0]
                                ),
                                timeout=2,
                            ))
                        except (asyncio.TimeoutError, Exception):
                            pass
                        results.append({"ip_address": ip, "hostname": hostname})
                except (asyncio.TimeoutError, subprocess.TimeoutExpired, OSError):
                    pass

        hosts = [str(ip) for ip in network.hosts()]
        # Hard overall timeout for the entire ping sweep
        try:
            await asyncio.wait_for(
                asyncio.gather(*[ping_host(ip) for ip in hosts]),
                timeout=max(timeout // 2, 30),
            )
        except asyncio.TimeoutError:
            logger.warning("Ping sweep timed out", subnet=subnet, found_so_far=len(results))
        return results

    async def _mdns_discovery(self) -> list[dict]:
        """mDNS discovery."""
        try:
            from zeroconf import Zeroconf, ServiceBrowser

            discovered = []
            zc = Zeroconf()

            class Listener:
                def __init__(self, z):
                    self.zc = z
                def remove_service(self, zc, t, n): pass
                def update_service(self, zc, t, n): pass
                def add_service(self, zc, type_, name):
                    try:
                        info = zc.get_service_info(type_, name, timeout=2000)
                        if info:
                            addrs = info.parsed_addresses()
                            discovered.append({
                                "name": name, "type": type_,
                                "ip": addrs[0] if addrs else None,
                                "port": info.port,
                                "hostname": info.server,
                            })
                    except Exception:
                        pass

            listener = Listener(zc)
            service_types = [
                "_http._tcp.local.", "_https._tcp.local.", "_ssh._tcp.local.",
                "_smb._tcp.local.", "_printer._tcp.local.", "_airplay._tcp.local.",
                "_googlecast._tcp.local.", "_hap._tcp.local.",
            ]

            browsers = []
            for st in service_types:
                try:
                    browsers.append(ServiceBrowser(zc, st, listener))
                except Exception:
                    pass

            await asyncio.sleep(3)
            zc.close()
            return discovered
        except (ImportError, OSError) as e:
            logger.debug("mDNS discovery unavailable", error=str(e))
            return []

    async def _ssdp_discovery(self) -> list[dict]:
        """SSDP discovery."""
        import socket as sock

        def search():
            s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM, sock.IPPROTO_UDP)
            s.settimeout(3)
            s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
            msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
            try:
                s.sendto(msg.encode(), ("239.255.255.250", 1900))
            except OSError:
                s.close()
                return []
            devices = []
            seen = set()
            try:
                while True:
                    data, addr = s.recvfrom(4096)
                    resp = data.decode("utf-8", errors="ignore")
                    headers = {}
                    for line in resp.split("\r\n"):
                        if ":" in line:
                            k, _, v = line.partition(":")
                            headers[k.strip().upper()] = v.strip()
                    loc = headers.get("LOCATION", "")
                    if loc and loc not in seen:
                        seen.add(loc)
                        devices.append({"ip": addr[0], "location": loc, "server": headers.get("SERVER", "")})
            except sock.timeout:
                pass
            finally:
                s.close()
            return devices

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, search)


class FingerprintService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.asset_service = AssetService(db)
        self.artifact_store = ArtifactStore(db)
        self.audit_trail = AuditTrail(db)

    async def run_fingerprinting(self, asset_id: str | None = None, run_id: str | None = None, timeout: int = 120) -> dict:
        """Run fingerprinting on one or all assets."""
        logger.info("Starting fingerprinting", asset_id=asset_id, run_id=run_id)

        await self.audit_trail.log(
            event_type="step_start", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="fingerprinting_start", run_id=run_id,
        )

        # Get target assets
        if asset_id:
            result = await self.db.execute(select(Asset).where(Asset.id == asset_id))
            asset = result.scalar_one_or_none()
            assets = [asset] if asset else []
        else:
            result = await self.db.execute(select(Asset))
            assets = list(result.scalars().all())

        fingerprinted = 0
        results_list = []

        for asset in assets:
            try:
                # Skip network fingerprinting if asset already has exposure data (demo/enriched)
                if asset.exposure and asset.os_guess:
                    logger.info("Asset already fingerprinted, skipping", ip=asset.ip_address)
                    results_list.append({
                        "target": asset.ip_address,
                        "open_ports": [],
                        "services": [],
                        "os": {"os_guess": asset.os_guess, "os_accuracy": 80, "method": "pre-populated"},
                        "exposure": asset.exposure,
                        "skipped": True,
                    })
                    fingerprinted += 1
                    continue

                fp_result = await self._fingerprint_asset(asset, timeout // max(len(assets), 1))
                results_list.append(fp_result)

                # Update asset with fingerprint data
                if fp_result.get("os", {}).get("os_guess"):
                    asset.os_guess = fp_result["os"]["os_guess"]
                if fp_result.get("exposure"):
                    asset.exposure = fp_result["exposure"]

                # Determine asset type from services + vendor
                asset_type = self._guess_asset_type(fp_result, vendor=asset.vendor, hostname=asset.hostname)
                if asset_type != "unknown":
                    asset.asset_type = asset_type
                    # Auto-assign zone and criticality based on detected type
                    asset.zone = self._assign_zone(asset_type)
                    asset.criticality = self._assign_criticality(asset_type)

                asset.last_seen = datetime.utcnow()
                fingerprinted += 1

            except Exception as e:
                logger.error("Fingerprinting failed for asset", ip=asset.ip_address, error=str(e))
                results_list.append({"target": asset.ip_address, "error": str(e)})

        # Store artifact
        await self.artifact_store.store(
            content=json.dumps(results_list, indent=2, default=str),
            artifact_type="raw_output",
            tool_name="fingerprint_service",
            target="all_assets" if not asset_id else asset_id,
            run_id=run_id,
            command=f"fingerprint asset_id={asset_id}",
            parameters={"asset_id": asset_id, "timeout": timeout},
        )

        await self.audit_trail.log(
            event_type="step_complete", entity_type="run",
            entity_id=run_id or "manual", actor="system",
            action="fingerprinting_complete", run_id=run_id,
            new_value={"fingerprinted": fingerprinted, "total_assets": len(assets)},
        )

        return {
            "status": "completed",
            "assets_fingerprinted": fingerprinted,
            "total_assets": len(assets),
            "results": results_list,
        }

    async def _fingerprint_asset(self, asset: Asset, timeout: int) -> dict:
        """Fingerprint a single asset: port scan + service detection + OS detection."""
        target = asset.ip_address

        # Port scan
        open_ports = []
        try:
            open_ports = await self._port_scan(target, timeout // 3)
        except Exception as e:
            logger.warning("Port scan failed", target=target, error=str(e))

        # Service detection
        services = []
        if open_ports:
            try:
                services = await self._service_detect(target, [p["port"] for p in open_ports])
            except Exception as e:
                logger.warning("Service detection failed", target=target, error=str(e))

        # OS detection (heuristic)
        os_info = await self._os_detect(target, open_ports)

        # Exposure indicators
        port_numbers = {p["port"] for p in open_ports}
        exposure = {
            "admin_ui": bool(port_numbers & {80, 443, 8080, 8443, 9090}),
            "ssh_exposed": 22 in port_numbers,
            "telnet_exposed": 23 in port_numbers,
            "smb_exposed": 445 in port_numbers,
            "upnp": bool(port_numbers & {1900, 5000}),
            "ftp_exposed": 21 in port_numbers,
        }

        return {
            "target": target,
            "open_ports": open_ports,
            "services": services,
            "os": os_info,
            "exposure": exposure,
        }

    async def _port_scan(self, target: str, timeout: int) -> list[dict]:
        """Scan top 50 ports."""
        TOP_PORTS = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445,
            465, 500, 548, 554, 587, 631, 993, 995, 1080, 1433, 1521, 1723,
            1883, 1900, 2049, 3000, 3306, 3389, 4443, 5000, 5001, 5060, 5222,
            5432, 5672, 5900, 5984, 6379, 6443, 8000, 8080, 8443, 8888, 9090,
            9200, 27017,
        ]
        sem = asyncio.Semaphore(100)
        open_ports: list[dict] = []

        PORT_NAMES = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
            161: "snmp", 443: "https", 445: "smb", 548: "afp", 554: "rtsp",
            587: "smtp", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1883: "mqtt", 1900: "ssdp", 3000: "http-alt", 3306: "mysql",
            3389: "rdp", 5000: "upnp", 5001: "synology", 5432: "postgresql",
            5672: "amqp", 5900: "vnc", 6379: "redis", 8000: "http-alt",
            8080: "http-proxy", 8443: "https-alt", 9090: "prometheus", 9200: "elasticsearch",
            27017: "mongodb",
        }

        async def check(port):
            async with sem:
                try:
                    r, w = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=2)
                    w.close()
                    await w.wait_closed()
                    open_ports.append({"port": port, "service": PORT_NAMES.get(port, "unknown")})
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        try:
            await asyncio.wait_for(
                asyncio.gather(*[check(p) for p in TOP_PORTS]),
                timeout=max(timeout, 30),
            )
        except asyncio.TimeoutError:
            logger.warning("Port scan timed out", target=target, found_so_far=len(open_ports))
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    async def _service_detect(self, target: str, ports: list[int]) -> list[dict]:
        """Basic service detection via banner grabbing."""
        services = []
        for port in ports[:20]:  # Limit to first 20 ports
            banner = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=3)
                try:
                    data = await asyncio.wait_for(r.read(512), timeout=2)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except asyncio.TimeoutError:
                    pass
                w.close()
                await w.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            services.append({"port": port, "banner": banner})
        return services

    async def _os_detect(self, target: str, open_ports: list[dict]) -> dict:
        """Heuristic OS detection."""
        ports = {p["port"] for p in open_ports}

        if {135, 139, 445}.issubset(ports):
            return {"os_guess": "Windows", "os_accuracy": 70, "method": "heuristic"}
        if 548 in ports:
            return {"os_guess": "macOS", "os_accuracy": 70, "method": "heuristic"}
        if {5000, 5001}.issubset(ports):
            return {"os_guess": "Synology DSM (Linux)", "os_accuracy": 80, "method": "heuristic"}
        if 22 in ports and 135 not in ports:
            return {"os_guess": "Linux", "os_accuracy": 50, "method": "heuristic"}
        if ports.issubset({80, 443, 8080}) and len(ports) > 0:
            return {"os_guess": "Embedded/Router", "os_accuracy": 40, "method": "heuristic"}

        return {"os_guess": "unknown", "os_accuracy": 0, "method": "heuristic"}

    # Vendor strings -> asset_type mapping (checked case-insensitively)
    _VENDOR_TYPE_MAP = {
        "meross": "iot",
        "tuya": "iot",
        "hikvision": "iot",
        "dahua": "iot",
        "philips": "iot",
        "signify": "iot",         # Philips Hue parent company
        "samsung electronics": "iot",
        "shelly": "iot",
        "sonoff": "iot",
        "tapo": "iot",
        "tp-link tapo": "iot",
        "ring": "iot",
        "wyze": "iot",
        "xiaomi": "iot",
        "espressif": "iot",       # ESP32/ESP8266 devices
        "avm": "router",          # Fritz!Box
        "fritzbox": "router",
        "fritz!box": "router",
        "netgear": "router",
        "asus networking": "router",
        "ubiquiti": "router",
        "mikrotik": "router",
        "tp-link": "router",      # generic TP-Link = router (tapo handled above)
    }

    # asset_type -> default zone
    _TYPE_ZONE_MAP = {
        "router": "lan",
        "workstation": "lan",
        "server": "lan",
        "nas": "lan",
        "sbc": "lan",
        "iot": "iot",
        "printer": "lan",
    }

    # asset_type -> default criticality
    _TYPE_CRITICALITY_MAP = {
        "router": "critical",
        "server": "high",
        "nas": "high",
        "workstation": "high",
        "sbc": "medium",
        "printer": "low",
        "iot": "low",
    }

    def _guess_asset_type(self, fp_result: dict, vendor: str | None = None, hostname: str | None = None) -> str:
        """Guess asset type from fingerprint results, vendor, and hostname."""
        os_guess = fp_result.get("os", {}).get("os_guess", "").lower()
        ports = {p["port"] for p in fp_result.get("open_ports", [])}

        # Check vendor first (more reliable than OS/port heuristics)
        if vendor:
            vendor_lower = vendor.lower()
            for vendor_key, asset_type in self._VENDOR_TYPE_MAP.items():
                if vendor_key in vendor_lower:
                    return asset_type

        # Hostname-based hints (e.g. "fritz.box")
        hostname = (hostname or "").lower()
        if "fritz" in hostname:
            return "router"

        if "synology" in os_guess:
            return "nas"
        if "router" in os_guess or "openwrt" in os_guess:
            return "router"
        if "windows" in os_guess:
            if 3389 in ports:
                return "workstation"
            return "workstation"
        if "macos" in os_guess:
            return "workstation"
        if "raspberry" in os_guess:
            return "sbc"
        if "embedded" in os_guess:
            return "iot"
        if os_guess == "linux":
            if 22 in ports and len(ports) <= 3:
                return "server"
            return "workstation"

        return "unknown"

    def _assign_zone(self, asset_type: str) -> str:
        """Assign network zone based on asset type."""
        return self._TYPE_ZONE_MAP.get(asset_type, "lan")

    def _assign_criticality(self, asset_type: str) -> str:
        """Assign criticality based on asset type."""
        return self._TYPE_CRITICALITY_MAP.get(asset_type, "medium")
