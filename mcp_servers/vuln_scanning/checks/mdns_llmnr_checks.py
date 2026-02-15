import asyncio
import socket
import struct
import structlog

logger = structlog.get_logger()


class MDNSLLMNRChecker:
    async def check(self, target: str, port: int = 5353, timeout: int = 10) -> list[dict]:
        logger.info("Starting mDNS/LLMNR check", target=target)
        findings = []

        # Check mDNS (port 5353)
        mdns_responds = await self._check_mdns(target, timeout)
        if mdns_responds:
            services = mdns_responds if isinstance(mdns_responds, str) else ""
            findings.append({
                "title": f"mDNS service exposed on {target}",
                "severity": "medium",
                "category": "misconfig",
                "description": (
                    f"Device at {target} responds to mDNS queries (UDP port 5353). "
                    f"mDNS can be abused for network reconnaissance and is susceptible to spoofing/poisoning attacks. "
                    f"Advertised services may leak device information."
                ),
                "remediation": (
                    "Disable mDNS/Bonjour if not needed. "
                    "If required, restrict mDNS to the local network segment using firewall rules. "
                    "On Linux: disable avahi-daemon. On macOS: disable Bonjour in firewall."
                ),
                "cwe_id": "CWE-290",
                "evidence": f"mDNS response received from {target}:5353{'. Services: ' + services if services else ''}",
            })

        # Check LLMNR (port 5355)
        llmnr_responds = await self._check_llmnr(target, timeout)
        if llmnr_responds:
            findings.append({
                "title": f"LLMNR service exposed on {target}",
                "severity": "medium",
                "category": "misconfig",
                "description": (
                    f"Device at {target} responds to LLMNR queries (UDP port 5355). "
                    f"LLMNR is susceptible to poisoning attacks that can capture credentials "
                    f"(e.g., using Responder). This is a common attack vector on Windows networks."
                ),
                "remediation": (
                    "Disable LLMNR via Group Policy: "
                    "Computer Configuration > Administrative Templates > Network > DNS Client > "
                    "Turn off multicast name resolution = Enabled. "
                    "Use DNS for name resolution instead."
                ),
                "cwe_id": "CWE-290",
                "evidence": f"LLMNR response received from {target}:5355",
            })

        if not findings:
            findings.append({
                "title": f"mDNS/LLMNR check on {target}",
                "severity": "info",
                "category": "info",
                "description": f"No mDNS or LLMNR services detected on {target}.",
                "evidence": f"No response from {target} on ports 5353/5355",
            })

        logger.info("mDNS/LLMNR check complete", target=target, finding_count=len(findings))
        return findings

    async def _check_mdns(self, target: str, timeout: int) -> str | bool:
        """Send mDNS query and check for response."""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._send_mdns_query, target),
                timeout=timeout,
            )
            return result
        except (asyncio.TimeoutError, Exception):
            return False

    def _send_mdns_query(self, target: str) -> str | bool:
        """Send mDNS PTR query for _services._dns-sd._udp.local."""
        # Build mDNS query for service enumeration
        txn_id = b"\x00\x00"
        flags = b"\x00\x00"  # Standard query
        questions = b"\x00\x01"
        answers = b"\x00\x00"
        authority = b"\x00\x00"
        additional = b"\x00\x00"
        header = txn_id + flags + questions + answers + authority + additional

        # Query name: _services._dns-sd._udp.local
        qname = (
            b"\x09_services"
            b"\x07_dns-sd"
            b"\x04_udp"
            b"\x05local"
            b"\x00"
        )
        qtype = struct.pack("!H", 12)   # PTR
        qclass = struct.pack("!H", 1)   # IN

        query = header + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(query, (target, 5353))
            data, _ = sock.recvfrom(4096)

            if data and len(data) > 12:
                # Try to extract advertised service names
                services = self._extract_service_names(data)
                return services if services else True
            return False
        except socket.timeout:
            return False
        finally:
            sock.close()

    def _extract_service_names(self, data: bytes) -> str:
        """Extract service names from mDNS response."""
        services = []
        try:
            # Parse answer count
            if len(data) < 12:
                return ""
            ancount = struct.unpack("!H", data[6:8])[0]
            if ancount == 0:
                return ""

            # Skip header and question section, look for readable strings
            idx = 12
            while idx < len(data) - 4:
                if data[idx] > 0 and data[idx] < 64:
                    length = data[idx]
                    if idx + 1 + length <= len(data):
                        try:
                            name = data[idx + 1:idx + 1 + length].decode("utf-8", errors="ignore")
                            if name.startswith("_") and len(name) > 2:
                                services.append(name)
                        except Exception:
                            pass
                idx += 1
        except Exception:
            pass
        return ", ".join(set(services)[:5]) if services else ""

    async def _check_llmnr(self, target: str, timeout: int) -> bool:
        """Send LLMNR query and check for response."""
        try:
            loop = asyncio.get_event_loop()
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._send_llmnr_query, target),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, Exception):
            return False

    def _send_llmnr_query(self, target: str) -> bool:
        """Send LLMNR name query."""
        import random

        txn_id = struct.pack("!H", random.randint(0, 65535))
        flags = b"\x00\x00"
        questions = b"\x00\x01"
        answers = b"\x00\x00"
        authority = b"\x00\x00"
        additional = b"\x00\x00"
        header = txn_id + flags + questions + answers + authority + additional

        # Query for "wpad" (common LLMNR query target)
        qname = b"\x04wpad\x00"
        qtype = struct.pack("!H", 1)   # A record
        qclass = struct.pack("!H", 1)  # IN

        query = header + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(query, (target, 5355))
            data, _ = sock.recvfrom(4096)
            return data is not None and len(data) > 12
        except socket.timeout:
            return False
        finally:
            sock.close()
