import asyncio
import ipaddress
import socket
import struct
import json
from datetime import datetime
from mcp_servers.common.schemas import AssetResult
import structlog

logger = structlog.get_logger()

# OUI vendor lookup (common home network vendors)
OUI_DATABASE: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:A0": "Dell",
    "00:25:00": "Apple",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1E:06": "ASUS",
    "2C:56:DC": "ASUS",
    "50:46:5D": "ASUS",
    "00:14:BF": "Linksys",
    "C0:56:27": "Belkin",
    "00:1F:33": "Netgear",
    "20:E5:2A": "Netgear",
    "A4:2B:8C": "Netgear",
    "00:26:F2": "Netgear",
    "C8:3A:35": "Tenda",
    "00:11:32": "Synology",
    "00:1B:21": "Intel",
    "3C:97:0E": "Intel",
    "A0:36:9F": "Intel",
    "00:1C:BF": "Intel",
    "00:0E:C6": "ASIX Electronics",
    "00:23:24": "Cisco",
    "F8:B1:56": "Dell",
    "D4:BE:D9": "Dell",
    "54:E1:AD": "LGIT",
    "AC:CF:5C": "Espressif (ESP8266/ESP32)",
    "24:6F:28": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "84:CC:A8": "Espressif (ESP8266/ESP32)",
    "60:01:94": "Espressif (ESP8266/ESP32)",
    "B4:E6:2D": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:25:E9": "TP-Link",
    "EC:08:6B": "TP-Link",
    "14:CC:20": "TP-Link",
    "98:DA:C4": "TP-Link",
    "00:17:88": "Philips Hue",
    "00:1D:C9": "Sonos",
    "B8:E9:37": "Sonos",
    "5C:AA:FD": "Sonos",
    "94:9F:3E": "Sonos",
    "78:28:CA": "Sonos",
    "34:7E:5C": "Ring",
    "00:04:20": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "F4:92:BF": "Ubiquiti",
    "18:E8:29": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "68:D7:9A": "Ubiquiti",
    "74:AC:B9": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "D0:21:F9": "Ubiquiti",
    "E0:63:DA": "Ubiquiti",
    "E8:48:B8": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "78:45:58": "Ubiquiti",
    "80:26:89": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
}


def lookup_vendor(mac: str) -> str | None:
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return OUI_DATABASE.get(prefix)


def resolve_hostname(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


class NetworkScanner:
    async def arp_scan(self, subnet: str, timeout: int = 30) -> list[AssetResult]:
        """Perform ARP scan using nmap or scapy fallback."""
        logger.info("Starting ARP scan", subnet=subnet, timeout=timeout)
        results: list[AssetResult] = []

        try:
            results = await self._nmap_arp_scan(subnet, timeout)
        except Exception as e:
            logger.warning("nmap ARP scan failed, trying scapy", error=str(e))
            try:
                results = await self._scapy_arp_scan(subnet, timeout)
            except Exception as e2:
                logger.warning("scapy ARP scan failed, trying ping fallback", error=str(e2))
                results = await self.ping_sweep(subnet, timeout)

        logger.info("ARP scan complete", subnet=subnet, hosts_found=len(results))
        return results

    async def _nmap_arp_scan(self, subnet: str, timeout: int) -> list[AssetResult]:
        """ARP scan using python-nmap."""
        import nmap
        nm = nmap.PortScanner()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: nm.scan(hosts=subnet, arguments=f"-sn -n --host-timeout {timeout}s"),
        )

        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = ""
                vendor = None
                if "mac" in nm[host]["addresses"]:
                    mac = nm[host]["addresses"]["mac"]
                    vendor = lookup_vendor(mac)
                    if not vendor and nm[host].get("vendor"):
                        vendor_dict = nm[host]["vendor"]
                        vendor = next(iter(vendor_dict.values()), None) if vendor_dict else None

                hostname = None
                if nm[host].hostname():
                    hostname = nm[host].hostname()
                if not hostname:
                    hostname = await asyncio.get_event_loop().run_in_executor(
                        None, resolve_hostname, host
                    )

                results.append(AssetResult(
                    ip_address=host,
                    mac_address=mac or None,
                    hostname=hostname,
                    vendor=vendor,
                ))

        return results

    async def _scapy_arp_scan(self, subnet: str, timeout: int) -> list[AssetResult]:
        """ARP scan using scapy."""
        from scapy.all import ARP, Ether, srp

        loop = asyncio.get_event_loop()

        def do_scan():
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            answered, _ = srp(packet, timeout=min(timeout, 10), verbose=False)
            return answered

        answered = await loop.run_in_executor(None, do_scan)

        results = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            hostname = await loop.run_in_executor(None, resolve_hostname, ip)
            vendor = lookup_vendor(mac)

            results.append(AssetResult(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
            ))

        return results

    async def ping_sweep(self, subnet: str, timeout: int = 30) -> list[AssetResult]:
        """Perform ICMP ping sweep using nmap or native ping."""
        logger.info("Starting ping sweep", subnet=subnet)
        results: list[AssetResult] = []

        try:
            results = await self._nmap_ping_sweep(subnet, timeout)
        except Exception as e:
            logger.warning("nmap ping sweep failed, trying native", error=str(e))
            results = await self._native_ping_sweep(subnet, timeout)

        logger.info("Ping sweep complete", hosts_found=len(results))
        return results

    async def _nmap_ping_sweep(self, subnet: str, timeout: int) -> list[AssetResult]:
        """Ping sweep using nmap."""
        import nmap
        nm = nmap.PortScanner()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: nm.scan(hosts=subnet, arguments=f"-sn --host-timeout {timeout}s"),
        )

        results = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = nm[host]["addresses"].get("mac", "")
                hostname = nm[host].hostname() or await loop.run_in_executor(
                    None, resolve_hostname, host
                )
                results.append(AssetResult(
                    ip_address=host,
                    mac_address=mac or None,
                    hostname=hostname,
                    vendor=lookup_vendor(mac),
                ))

        return results

    async def _native_ping_sweep(self, subnet: str, timeout: int) -> list[AssetResult]:
        """Ping sweep using native OS ping command."""
        import platform
        network = ipaddress.ip_network(subnet, strict=False)

        # Limit to /24 or smaller to avoid excessive pings
        if network.num_addresses > 256:
            logger.warning("Subnet too large for native ping, limiting to first 256 addresses")
            network = ipaddress.ip_network(f"{network.network_address}/24", strict=False)

        sem = asyncio.Semaphore(50)
        results: list[AssetResult] = []

        async def ping_host(ip: str):
            async with sem:
                try:
                    if platform.system().lower() == "windows":
                        cmd = ["ping", "-n", "1", "-w", "1000", ip]
                    else:
                        cmd = ["ping", "-c", "1", "-W", "1", ip]

                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), timeout=3)

                    if proc.returncode == 0:
                        hostname = await asyncio.get_event_loop().run_in_executor(
                            None, resolve_hostname, ip
                        )
                        results.append(AssetResult(
                            ip_address=ip,
                            hostname=hostname,
                        ))
                except (asyncio.TimeoutError, OSError):
                    pass

        hosts = [str(ip) for ip in network.hosts()]
        await asyncio.gather(*[ping_host(ip) for ip in hosts])

        return results
