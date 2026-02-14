import asyncio
import socket
import struct
import structlog

logger = structlog.get_logger()


class DNSChecker:
    async def check(self, target: str, port: int = 53) -> list[dict]:
        logger.info("Starting DNS check", target=target, port=port)
        findings = []

        # Check if DNS is responding
        is_responding = await self._dns_query(target, port, "google.com")
        if not is_responding:
            return [{
                "title": f"DNS service on port {port} not responding",
                "severity": "info",
                "category": "info",
                "description": "DNS service did not respond to queries.",
                "evidence": f"No response from {target}:{port}",
            }]

        findings.append({
            "title": "DNS service is responding",
            "severity": "info",
            "category": "info",
            "description": f"DNS server at {target}:{port} responds to queries.",
            "evidence": f"DNS query to {target}:{port} successful",
        })

        # Check for open resolver (recursive queries from external)
        is_recursive = await self._check_recursive(target, port)
        if is_recursive:
            findings.append({
                "title": "DNS server allows recursive queries",
                "severity": "medium",
                "category": "misconfig",
                "description": "DNS server accepts recursive queries. If exposed externally, this can be abused for DNS amplification attacks.",
                "remediation": "Restrict recursive queries to trusted networks only, or disable recursion if the server is authoritative only.",
                "cwe_id": "CWE-406",
                "evidence": "Recursive query for external domain succeeded",
            })

        # Check for DNSSEC
        has_dnssec = await self._check_dnssec(target, port)
        if not has_dnssec:
            findings.append({
                "title": "DNSSEC validation not detected",
                "severity": "low",
                "category": "misconfig",
                "description": "DNS resolver does not appear to validate DNSSEC signatures, allowing potential DNS spoofing.",
                "remediation": "Enable DNSSEC validation on the DNS resolver.",
                "cwe_id": "CWE-345",
                "evidence": "No DNSSEC (AD flag) in response",
            })

        # Check for DNS over TLS/HTTPS support
        dot_supported = await self._check_dot(target)
        if not dot_supported:
            findings.append({
                "title": "DNS-over-TLS (DoT) not available",
                "severity": "low",
                "category": "info",
                "description": "DNS queries are sent in plaintext. DNS-over-TLS encrypts DNS traffic.",
                "remediation": "Configure DNS server to support DNS-over-TLS on port 853.",
                "evidence": f"Port 853 not open on {target}",
            })

        # Check for zone transfer
        zone_transfer = await self._check_zone_transfer(target, port)
        if zone_transfer:
            findings.append({
                "title": "DNS zone transfer (AXFR) allowed",
                "severity": "high",
                "category": "misconfig",
                "description": "DNS server allows zone transfers, potentially exposing all DNS records.",
                "remediation": "Restrict zone transfers to authorized secondary DNS servers only.",
                "cwe_id": "CWE-200",
                "evidence": "AXFR query returned data",
            })

        logger.info("DNS check complete", target=target, finding_count=len(findings))
        return findings

    async def _dns_query(self, target: str, port: int, domain: str) -> bool:
        try:
            query = self._build_dns_query(domain)
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_udp_query, target, port, query)
            return response is not None and len(response) > 12
        except Exception:
            return False

    async def _check_recursive(self, target: str, port: int) -> bool:
        try:
            query = self._build_dns_query("example.com", recursive=True)
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_udp_query, target, port, query)
            if response and len(response) > 12:
                flags = struct.unpack("!H", response[2:4])[0]
                ra_bit = (flags >> 7) & 1  # Recursion Available
                return ra_bit == 1
        except Exception:
            pass
        return False

    async def _check_dnssec(self, target: str, port: int) -> bool:
        try:
            query = self._build_dns_query("example.com", recursive=True, dnssec=True)
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_udp_query, target, port, query)
            if response and len(response) > 12:
                flags = struct.unpack("!H", response[2:4])[0]
                ad_bit = (flags >> 5) & 1  # Authenticated Data
                return ad_bit == 1
        except Exception:
            pass
        return False

    async def _check_dot(self, target: str) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 853), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _check_zone_transfer(self, target: str, port: int) -> bool:
        # Simplified AXFR check - just see if TCP connects and responds
        try:
            query = self._build_dns_query(".", qtype=252)  # AXFR type
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._send_tcp_query, target, port, query)
            if response and len(response) > 12:
                rcode = struct.unpack("!H", response[2:4])[0] & 0xF
                return rcode == 0  # NOERROR means transfer was accepted
        except Exception:
            pass
        return False

    def _build_dns_query(self, domain: str, recursive: bool = True, dnssec: bool = False, qtype: int = 1) -> bytes:
        import random
        txn_id = random.randint(0, 65535)
        flags = 0x0100 if recursive else 0x0000
        if dnssec:
            flags |= 0x0020  # AD flag
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

        question = b""
        for label in domain.rstrip(".").split("."):
            if label:
                question += struct.pack("B", len(label)) + label.encode()
        question += b"\x00"
        question += struct.pack("!HH", qtype, 1)  # Type A (or AXFR), Class IN

        return header + question

    def _send_udp_query(self, target: str, port: int, query: bytes) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(query, (target, port))
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        finally:
            sock.close()

    def _send_tcp_query(self, target: str, port: int, query: bytes) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((target, port))
            # TCP DNS prepends 2-byte length
            length = struct.pack("!H", len(query))
            sock.sendall(length + query)
            data = sock.recv(4096)
            return data[2:] if len(data) > 2 else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            sock.close()
