import asyncio
import socket
import ssl
import struct
from datetime import datetime
import structlog

logger = structlog.get_logger()

# Top 100 most common ports
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111,
    113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 389,
    443, 445, 464, 465, 500, 514, 515, 520, 521, 543, 544, 548, 554,
    587, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1434, 1521,
    1701, 1723, 1812, 1813, 1883, 1900, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4443,
    4444, 5000, 5001, 5060, 5222, 5432, 5555, 5601, 5672, 5900, 5984,
    6000, 6379, 6443, 6667, 7001, 7077, 8000, 8008, 8080, 8443, 8888,
    9090, 9200, 9418, 27017,
]

# Service name mapping for common ports
PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 500: "ike",
    514: "syslog", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 1900: "ssdp", 2049: "nfs",
    3000: "grafana", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
    5000: "upnp", 5001: "synology", 5060: "sip", 5222: "xmpp",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 27017: "mongodb",
}


class PortScanner:
    async def scan(self, target: str, ports_spec: str = "top100", timeout: int = 60) -> dict:
        """Scan ports on target host."""
        logger.info("Starting port scan", target=target, ports=ports_spec)

        ports = self._parse_ports(ports_spec)
        sem = asyncio.Semaphore(100)
        open_ports: list[dict] = []

        async def check_port(port: int):
            async with sem:
                try:
                    fut = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=2)
                    writer.close()
                    await writer.wait_closed()

                    service = PORT_SERVICE_MAP.get(port, "unknown")
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service,
                    })
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        await asyncio.gather(*[check_port(p) for p in ports])
        open_ports.sort(key=lambda x: x["port"])

        logger.info("Port scan complete", target=target, open_count=len(open_ports))
        return {
            "target": target,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "scan_time": datetime.utcnow().isoformat(),
        }

    def _parse_ports(self, spec: str) -> list[int]:
        if spec == "top100":
            return TOP_100_PORTS

        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)


class ServiceProbe:
    async def detect_services(self, target: str, ports: list[int] | None = None, timeout: int = 60) -> dict:
        """Detect services on open ports via banner grabbing and protocol probes."""
        if not ports:
            scanner = PortScanner()
            scan_results = await scanner.scan(target, "top100", timeout)
            ports = [p["port"] for p in scan_results.get("open_ports", [])]

        logger.info("Starting service detection", target=target, ports=ports)
        services = []

        for port in ports:
            try:
                service_info = await self._probe_port(target, port)
                if service_info:
                    services.append(service_info)
            except Exception as e:
                logger.debug("Probe failed", target=target, port=port, error=str(e))
                services.append({
                    "port": port,
                    "service": PORT_SERVICE_MAP.get(port, "unknown"),
                    "version": None,
                    "banner": None,
                })

        return {"target": target, "services": services}

    async def _probe_port(self, target: str, port: int) -> dict | None:
        """Probe a single port for service information."""
        service = PORT_SERVICE_MAP.get(port, "unknown")
        banner = None
        version = None
        tls = False

        try:
            # Try TLS first for known TLS ports
            if port in (443, 465, 636, 993, 995, 4443, 8443, 6443):
                tls = True
                banner, version = await self._tls_probe(target, port)
            else:
                # Try plain TCP banner grab
                banner = await self._banner_grab(target, port)
                if banner:
                    version = self._extract_version(banner, service)

                # If no banner on HTTP ports, try HTTP probe
                if not banner and port in (80, 8080, 8000, 8008, 8888, 3000, 9090):
                    banner, version = await self._http_probe(target, port, use_tls=False)

        except Exception as e:
            logger.debug("Service probe failed", target=target, port=port, error=str(e))

        return {
            "port": port,
            "service": service,
            "version": version,
            "banner": banner[:500] if banner else None,
            "tls": tls,
        }

    async def _banner_grab(self, target: str, port: int, timeout: float = 3) -> str | None:
        """Grab banner from a TCP service."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )

            # Some services send banner immediately
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner = data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                # Try sending a probe
                writer.write(b"\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    banner = data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    banner = None

            writer.close()
            await writer.wait_closed()
            return banner if banner else None

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def _http_probe(self, target: str, port: int, use_tls: bool = False) -> tuple[str | None, str | None]:
        """Send HTTP HEAD request to detect web servers."""
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ctx), timeout=5
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=5
                )

            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            response = data.decode("utf-8", errors="replace")
            writer.close()
            await writer.wait_closed()

            server_header = None
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    server_header = line.split(":", 1)[1].strip()
                    break

            return response[:500], server_header

        except Exception:
            return None, None

    async def _tls_probe(self, target: str, port: int) -> tuple[str | None, str | None]:
        """Probe TLS service for certificate and protocol info."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx), timeout=5
            )

            # Get SSL info
            ssl_obj = writer.get_extra_info("ssl_object")
            version = ssl_obj.version() if ssl_obj else None
            cipher = ssl_obj.cipher() if ssl_obj else None

            # Try HTTP probe over TLS
            banner = None
            try:
                request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=3)
                banner = data.decode("utf-8", errors="replace")[:500]
            except Exception:
                pass

            writer.close()
            await writer.wait_closed()

            tls_info = f"TLS {version}" if version else "TLS"
            if cipher:
                tls_info += f" ({cipher[0]})"

            return banner, tls_info

        except Exception:
            return None, None

    def _extract_version(self, banner: str, service: str) -> str | None:
        """Extract version information from service banner."""
        if not banner:
            return None

        banner_lower = banner.lower()

        # SSH
        if banner_lower.startswith("ssh-"):
            return banner.split("\n")[0].strip()

        # FTP
        if "ftp" in banner_lower and ("220" in banner or "vsftpd" in banner_lower):
            return banner.split("\n")[0].strip()

        # SMTP
        if "smtp" in banner_lower or banner.startswith("220"):
            return banner.split("\n")[0].strip()

        return banner.split("\n")[0][:100].strip() if banner else None


class OSDetector:
    async def detect(self, target: str) -> dict:
        """Attempt OS fingerprinting based on open ports and service banners."""
        logger.info("Starting OS detection", target=target)

        try:
            return await self._nmap_os_detect(target)
        except Exception as e:
            logger.debug("nmap OS detection failed, using heuristic", error=str(e))
            return await self._heuristic_detect(target)

    async def _nmap_os_detect(self, target: str) -> dict:
        """OS detection using nmap."""
        import nmap
        nm = nmap.PortScanner()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: nm.scan(hosts=target, arguments="-O --host-timeout 30s"),
        )

        if target in nm.all_hosts():
            os_matches = nm[target].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                return {
                    "os_guess": best.get("name", "unknown"),
                    "os_accuracy": int(best.get("accuracy", 0)),
                    "os_family": best.get("osclass", [{}])[0].get("osfamily", "unknown") if best.get("osclass") else "unknown",
                    "method": "nmap",
                }

        return {"os_guess": "unknown", "os_accuracy": 0, "os_family": "unknown", "method": "nmap"}

    async def _heuristic_detect(self, target: str) -> dict:
        """Heuristic OS detection based on port profile and banners."""
        scanner = PortScanner()
        results = await scanner.scan(target, "22,80,135,139,443,445,548,3389,5000,5001,8080,62078")
        open_ports = {p["port"] for p in results.get("open_ports", [])}

        os_guess = "unknown"
        confidence = 0

        # Windows indicators
        if {135, 139, 445}.issubset(open_ports):
            os_guess = "Windows"
            confidence = 70
            if 3389 in open_ports:
                confidence = 85

        # macOS indicators
        elif 548 in open_ports:  # AFP
            os_guess = "macOS"
            confidence = 75
            if 62078 in open_ports:  # iphone-sync
                os_guess = "iOS/macOS"
                confidence = 80

        # Synology NAS
        elif {5000, 5001}.issubset(open_ports):
            os_guess = "Synology DSM (Linux)"
            confidence = 80

        # Linux indicators
        elif 22 in open_ports and 135 not in open_ports:
            os_guess = "Linux"
            confidence = 50
            # Try SSH banner
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, 22), timeout=3
                )
                data = await asyncio.wait_for(reader.read(256), timeout=2)
                banner = data.decode("utf-8", errors="replace").strip()
                writer.close()
                await writer.wait_closed()

                if "ubuntu" in banner.lower():
                    os_guess = "Ubuntu Linux"
                    confidence = 75
                elif "debian" in banner.lower():
                    os_guess = "Debian Linux"
                    confidence = 75
                elif "raspbian" in banner.lower() or "raspberry" in banner.lower():
                    os_guess = "Raspberry Pi OS (Linux)"
                    confidence = 80
                elif "openwrt" in banner.lower():
                    os_guess = "OpenWrt (Linux)"
                    confidence = 85
            except Exception:
                pass

        # Router/IoT with only HTTP
        elif open_ports.issubset({80, 443, 8080}) and len(open_ports) > 0:
            os_guess = "Embedded/Router"
            confidence = 40

        return {
            "os_guess": os_guess,
            "os_accuracy": confidence,
            "os_family": os_guess.split("(")[0].strip() if "(" in os_guess else os_guess,
            "method": "heuristic",
            "indicators": list(open_ports),
        }
