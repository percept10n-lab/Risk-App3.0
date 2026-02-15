import asyncio
import socket
import struct
import structlog

logger = structlog.get_logger()

# SNMP v2c GET sysDescr OID: 1.3.6.1.2.1.1.1.0
SYSDESCR_OID = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
# sysName OID: 1.3.6.1.2.1.1.5.0
SYSNAME_OID = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00"

DEFAULT_COMMUNITIES = ["public", "private", "community"]


class SNMPChecker:
    async def check(self, target: str, port: int = 161, timeout: int = 10) -> list[dict]:
        logger.info("Starting SNMP check", target=target, port=port)
        findings = []

        for community in DEFAULT_COMMUNITIES:
            try:
                response = await asyncio.wait_for(
                    self._snmp_get(target, port, community),
                    timeout=timeout,
                )
                if response:
                    sys_descr = self._extract_string(response)
                    findings.append({
                        "title": f"SNMP service with default community string '{community}' on {target}",
                        "severity": "high",
                        "category": "vuln",
                        "description": (
                            f"SNMP v2c service on {target}:{port} responds to the default community string '{community}'. "
                            f"This allows unauthorized read access to device information and potentially configuration data."
                        ),
                        "remediation": (
                            "Change the SNMP community string to a non-default value. "
                            "Consider using SNMPv3 with authentication and encryption. "
                            "Restrict SNMP access to management stations only."
                        ),
                        "cwe_id": "CWE-200",
                        "evidence": f"SNMP GET sysDescr with community='{community}' returned: {sys_descr or 'response received'}",
                    })
                    # Only report the first community that works
                    break
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug("SNMP community check failed", target=target, community=community, error=str(e))

        if not findings:
            findings.append({
                "title": f"SNMP service check on {target}",
                "severity": "info",
                "category": "info",
                "description": f"SNMP service on {target}:{port} did not respond to default community strings.",
                "evidence": f"No response from {target}:{port} with default communities",
            })

        logger.info("SNMP check complete", target=target, finding_count=len(findings))
        return findings

    async def _snmp_get(self, target: str, port: int, community: str) -> bytes | None:
        """Send SNMP v2c GET request for sysDescr."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._send_snmp_get, target, port, community
        )

    def _send_snmp_get(self, target: str, port: int, community: str) -> bytes | None:
        """Build and send an SNMP v2c GET-request packet."""
        # Build SNMP v2c GET packet
        community_bytes = community.encode()

        # Variable binding: sysDescr OID with NULL value
        varbind = SYSDESCR_OID + b"\x05\x00"  # NULL
        varbind_seq = b"\x30" + bytes([len(varbind)]) + varbind
        varbind_list = b"\x30" + bytes([len(varbind_seq)]) + varbind_seq

        # PDU: GET-request (0xa0)
        request_id = b"\x02\x01\x01"  # INTEGER 1
        error_status = b"\x02\x01\x00"  # INTEGER 0
        error_index = b"\x02\x01\x00"  # INTEGER 0
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content

        # SNMP message
        version = b"\x02\x01\x01"  # INTEGER 1 (SNMPv2c)
        community_tlv = b"\x04" + bytes([len(community_bytes)]) + community_bytes
        message_content = version + community_tlv + pdu
        message = b"\x30" + bytes([len(message_content)]) + message_content

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(message, (target, port))
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        finally:
            sock.close()

    def _extract_string(self, response: bytes) -> str | None:
        """Try to extract a readable string from SNMP response."""
        try:
            # Look for OCTET STRING (0x04) in the response
            idx = 0
            while idx < len(response) - 2:
                if response[idx] == 0x04 and response[idx + 1] > 0:
                    length = response[idx + 1]
                    value = response[idx + 2:idx + 2 + length]
                    decoded = value.decode("utf-8", errors="replace")
                    if len(decoded) > 3:  # Skip short values
                        return decoded
                idx += 1
        except Exception:
            pass
        return None
