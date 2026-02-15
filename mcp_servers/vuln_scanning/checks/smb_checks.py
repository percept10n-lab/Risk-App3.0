import asyncio
import socket
import struct
import structlog

logger = structlog.get_logger()

# SMB1 Negotiate request
SMB1_NEGOTIATE = (
    b"\x00"          # Session message
    b"\x00\x00\x45"  # Length (placeholder, adjusted below)
    b"\xff\x53\x4d\x42"  # SMB magic
    b"\x72"          # Command: Negotiate
    b"\x00\x00\x00\x00"  # Status
    b"\x08"          # Flags
    b"\x01\xc0"      # Flags2
    b"\x00" * 12     # Padding
    b"\x00\x00"      # Tree ID
    b"\x00\x01"      # Process ID
    b"\x00\x00"      # User ID
    b"\x00\x00"      # Multiplex ID
    b"\x00"          # Word count
    b"\x12\x00"      # Byte count
    b"\x02"          # Dialect buffer format
    b"\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12
    b"\x02"
    b"\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"  # SMB 2.002
)


class SMBChecker:
    async def check(self, target: str, port: int = 445, timeout: int = 10) -> list[dict]:
        logger.info("Starting SMB check", target=target, port=port)
        findings = []

        # Check SMB connectivity and negotiate
        try:
            response = await asyncio.wait_for(
                self._smb_negotiate(target, port),
                timeout=timeout,
            )

            if response:
                # Check for SMBv1 support
                if self._detect_smbv1(response):
                    findings.append({
                        "title": f"SMBv1 protocol enabled on {target}",
                        "severity": "critical",
                        "category": "vuln",
                        "description": (
                            f"The SMB service on {target}:{port} supports SMBv1 (NT LM 0.12). "
                            f"SMBv1 is vulnerable to multiple critical exploits including EternalBlue (MS17-010)."
                        ),
                        "remediation": (
                            "Disable SMBv1 on the device. Use SMBv2 or SMBv3 only. "
                            "On Windows: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                        ),
                        "cwe_id": "CWE-327",
                        "cve_ids": ["CVE-2017-0144"],
                        "evidence": f"SMBv1 negotiate response received from {target}:{port}",
                    })

                # Check for SMB signing
                if not self._check_signing_required(response):
                    findings.append({
                        "title": f"SMB signing not required on {target}",
                        "severity": "high",
                        "category": "misconfig",
                        "description": (
                            f"The SMB service on {target}:{port} does not require message signing. "
                            f"This allows potential man-in-the-middle and relay attacks."
                        ),
                        "remediation": (
                            "Enable mandatory SMB signing. "
                            "On Windows: Set 'Microsoft network server: Digitally sign communications (always)' to Enabled."
                        ),
                        "cwe_id": "CWE-311",
                        "evidence": f"SMB signing not required flag in negotiate response from {target}:{port}",
                    })
            else:
                findings.append({
                    "title": f"SMB service detected on {target}",
                    "severity": "info",
                    "category": "info",
                    "description": f"SMB service on {target}:{port} accepted connection but did not return parseable response.",
                    "evidence": f"TCP connection to {target}:{port} succeeded",
                })

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.debug("SMB check failed", target=target, error=str(e))
            return findings

        # Try null session
        try:
            null_session = await asyncio.wait_for(
                self._try_null_session(target, port),
                timeout=timeout,
            )
            if null_session:
                findings.append({
                    "title": f"SMB null session allowed on {target}",
                    "severity": "high",
                    "category": "vuln",
                    "description": (
                        f"The SMB service on {target}:{port} allows null session connections (IPC$). "
                        f"This can expose user lists, share enumeration, and other sensitive information."
                    ),
                    "remediation": (
                        "Disable null session access. "
                        "Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to Enabled."
                    ),
                    "cwe_id": "CWE-284",
                    "evidence": f"Null session IPC$ connection succeeded on {target}:{port}",
                })
        except Exception as e:
            logger.debug("Null session check failed", target=target, error=str(e))

        logger.info("SMB check complete", target=target, finding_count=len(findings))
        return findings

    async def _smb_negotiate(self, target: str, port: int) -> bytes | None:
        """Send SMB negotiate request and return response."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._send_negotiate, target, port)

    def _send_negotiate(self, target: str, port: int) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((target, port))
            sock.sendall(SMB1_NEGOTIATE)
            data = sock.recv(4096)
            return data if data else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            sock.close()

    def _detect_smbv1(self, response: bytes) -> bool:
        """Check if response indicates SMBv1 support."""
        # Look for SMB1 magic: 0xFF 'S' 'M' 'B'
        return b"\xff\x53\x4d\x42" in response

    def _check_signing_required(self, response: bytes) -> bool:
        """Check if SMB signing is required in the response."""
        try:
            # In SMB1 negotiate response, security mode is at offset 39 (after NetBIOS header)
            if len(response) > 39:
                # Find SMB header
                smb_offset = response.find(b"\xff\x53\x4d\x42")
                if smb_offset >= 0 and len(response) > smb_offset + 39:
                    # Security mode byte: bit 1 = signing enabled, bit 2 = signing required
                    sec_mode = response[smb_offset + 35]
                    return bool(sec_mode & 0x08)  # Signing required bit
        except Exception:
            pass
        return False

    async def _try_null_session(self, target: str, port: int) -> bool:
        """Attempt null session connection to IPC$."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._attempt_null_session, target, port)

    def _attempt_null_session(self, target: str, port: int) -> bool:
        """Try to establish a null session via SMB."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((target, port))
            # Send negotiate
            sock.sendall(SMB1_NEGOTIATE)
            data = sock.recv(4096)
            if not data or b"\xff\x53\x4d\x42" not in data:
                return False

            # Build session setup with empty credentials
            session_setup = bytearray(
                b"\x00\x00\x00\x4f"  # Length
                b"\xff\x53\x4d\x42"  # SMB magic
                b"\x73"              # Command: Session Setup
                b"\x00\x00\x00\x00"  # Status
                b"\x08"              # Flags
                b"\x01\xc0"          # Flags2
                b"\x00" * 12         # Padding
                b"\x00\x00"          # Tree ID
                b"\x00\x01"          # Process ID
                b"\x00\x00"          # User ID
                b"\x00\x01"          # Multiplex ID
                b"\x0d"              # Word count: 13
                b"\xff"              # AndX command: none
                b"\x00"              # Reserved
                b"\x00\x00"          # AndX offset
                b"\x04\x11"          # Max buffer
                b"\x01\x00"          # Max mpx
                b"\x00\x00"          # VC number
                b"\x00\x00\x00\x00"  # Session key
                b"\x01\x00"          # Security blob length
                b"\x00\x00"          # Reserved
                b"\x00\x00\x00\x00"  # Capabilities
                b"\x01\x00"          # Byte count
                b"\x00"              # Security blob (null)
            )
            sock.sendall(bytes(session_setup))
            response = sock.recv(4096)

            if response and b"\xff\x53\x4d\x42" in response:
                # Check NT status code for success (0x00000000) or MORE_PROCESSING (0xc0000016)
                smb_offset = response.find(b"\xff\x53\x4d\x42")
                if smb_offset >= 0 and len(response) > smb_offset + 9:
                    status = struct.unpack("<I", response[smb_offset + 5:smb_offset + 9])[0]
                    return status == 0x00000000
            return False
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()
