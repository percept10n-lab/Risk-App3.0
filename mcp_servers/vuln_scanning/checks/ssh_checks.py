import asyncio
import structlog

logger = structlog.get_logger()

WEAK_KEY_EXCHANGE = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "des-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}
WEAK_HOST_KEYS = {"ssh-dss"}


class SSHChecker:
    async def check(self, target: str, port: int = 22) -> list[dict]:
        logger.info("Starting SSH check", target=target, port=port)
        findings = []

        # Get SSH banner
        banner = await self._get_banner(target, port)
        if not banner:
            return [{
                "title": f"SSH service on port {port} not responding",
                "severity": "info",
                "category": "info",
                "description": "Could not connect to SSH service or no banner received.",
                "evidence": "Connection failed or timeout",
            }]

        findings.append({
            "title": f"SSH service detected: {banner[:80]}",
            "severity": "info",
            "category": "info",
            "description": f"SSH server banner: {banner}",
            "evidence": f"Banner: {banner}",
        })

        # Check for old SSH versions
        banner_lower = banner.lower()
        if "ssh-1" in banner_lower and "ssh-2" not in banner_lower:
            findings.append({
                "title": "SSH protocol version 1 detected",
                "severity": "critical",
                "category": "vuln",
                "description": "SSH v1 has known cryptographic weaknesses and should not be used.",
                "remediation": "Disable SSH v1 and use only SSH v2.",
                "cwe_id": "CWE-327",
                "evidence": f"Banner indicates SSH v1: {banner}",
            })

        # Check for known vulnerable versions
        if "openssh" in banner_lower:
            version = self._extract_openssh_version(banner)
            if version:
                findings.append({
                    "title": f"OpenSSH version: {version}",
                    "severity": "info",
                    "category": "info",
                    "description": f"OpenSSH {version} detected. Check for known CVEs.",
                    "evidence": f"Version: {version}",
                })
                # Check for notably old versions
                try:
                    major, minor = version.split(".")[:2]
                    major_int = int(major)
                    minor_int = int(minor.split("p")[0])
                    if major_int < 7 or (major_int == 7 and minor_int < 4):
                        findings.append({
                            "title": f"Outdated OpenSSH version {version}",
                            "severity": "high",
                            "category": "vuln",
                            "description": f"OpenSSH {version} is significantly outdated and may contain known vulnerabilities.",
                            "remediation": "Update OpenSSH to the latest stable version.",
                            "cwe_id": "CWE-1104",
                            "evidence": f"Detected version {version}, recommended >= 8.0",
                        })
                except (ValueError, IndexError):
                    pass

        if "dropbear" in banner_lower:
            findings.append({
                "title": "Dropbear SSH server detected",
                "severity": "info",
                "category": "info",
                "description": "Dropbear is a lightweight SSH server common on embedded devices and routers.",
                "evidence": f"Banner: {banner}",
            })

        # Try paramiko for detailed algorithm check
        try:
            algo_findings = await self._check_algorithms(target, port)
            findings.extend(algo_findings)
        except Exception as e:
            logger.debug("Algorithm check failed", error=str(e))

        # Check for password authentication
        try:
            auth_findings = await self._check_auth_methods(target, port)
            findings.extend(auth_findings)
        except Exception as e:
            logger.debug("Auth method check failed", error=str(e))

        logger.info("SSH check complete", target=target, finding_count=len(findings))
        return findings

    async def _get_banner(self, target: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=5
            )
            data = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()
            await writer.wait_closed()
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    def _extract_openssh_version(self, banner: str) -> str | None:
        import re
        match = re.search(r"OpenSSH[_\s](\d+\.\d+(?:p\d+)?)", banner, re.IGNORECASE)
        return match.group(1) if match else None

    async def _check_algorithms(self, target: str, port: int) -> list[dict]:
        findings = []
        try:
            import paramiko
            transport = paramiko.Transport((target, port))
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: transport.connect()),
                timeout=10,
            )

            # Get negotiated algorithms
            security_options = transport.get_security_options()

            # Check key exchange
            kex = set(security_options.kex)
            weak_kex = kex & WEAK_KEY_EXCHANGE
            if weak_kex:
                findings.append({
                    "title": f"Weak SSH key exchange algorithms supported",
                    "severity": "medium",
                    "category": "misconfig",
                    "description": f"Server supports weak key exchange: {', '.join(weak_kex)}",
                    "remediation": "Disable weak key exchange algorithms in SSH server configuration.",
                    "cwe_id": "CWE-327",
                    "evidence": f"Weak KEX: {', '.join(weak_kex)}",
                })

            # Check ciphers
            ciphers = set(security_options.ciphers)
            weak_c = ciphers & WEAK_CIPHERS
            if weak_c:
                findings.append({
                    "title": "Weak SSH cipher algorithms supported",
                    "severity": "medium",
                    "category": "misconfig",
                    "description": f"Server supports weak ciphers: {', '.join(weak_c)}",
                    "remediation": "Disable weak ciphers. Use AES-CTR or AES-GCM ciphers.",
                    "cwe_id": "CWE-327",
                    "evidence": f"Weak ciphers: {', '.join(weak_c)}",
                })

            # Check MACs
            digests = set(security_options.digests)
            weak_m = digests & WEAK_MACS
            if weak_m:
                findings.append({
                    "title": "Weak SSH MAC algorithms supported",
                    "severity": "low",
                    "category": "misconfig",
                    "description": f"Server supports weak MAC algorithms: {', '.join(weak_m)}",
                    "remediation": "Disable weak MACs. Use HMAC-SHA2 or UMAC-128.",
                    "cwe_id": "CWE-327",
                    "evidence": f"Weak MACs: {', '.join(weak_m)}",
                })

            # Check host key types
            keys = set(security_options.key_types)
            weak_k = keys & WEAK_HOST_KEYS
            if weak_k:
                findings.append({
                    "title": "Weak SSH host key type: DSA",
                    "severity": "medium",
                    "category": "misconfig",
                    "description": "Server uses DSA host keys which are considered weak.",
                    "remediation": "Generate ED25519 or RSA (4096-bit) host keys.",
                    "cwe_id": "CWE-326",
                    "evidence": f"Weak host keys: {', '.join(weak_k)}",
                })

            transport.close()
        except ImportError:
            logger.debug("paramiko not available for algorithm check")
        except Exception as e:
            logger.debug("SSH algorithm check failed", error=str(e))

        return findings

    async def _check_auth_methods(self, target: str, port: int) -> list[dict]:
        findings = []
        try:
            import paramiko
            transport = paramiko.Transport((target, port))
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: transport.connect()),
                timeout=10,
            )

            try:
                transport.auth_none("")
            except paramiko.BadAuthenticationType as e:
                auth_methods = e.allowed_types
                if "password" in auth_methods:
                    findings.append({
                        "title": "SSH password authentication enabled",
                        "severity": "medium",
                        "category": "misconfig",
                        "description": "Password authentication is enabled, which is susceptible to brute-force attacks.",
                        "remediation": "Disable password authentication and use key-based authentication only.",
                        "cwe_id": "CWE-307",
                        "evidence": f"Allowed auth methods: {', '.join(auth_methods)}",
                    })
                if "publickey" in auth_methods:
                    findings.append({
                        "title": "SSH public key authentication supported",
                        "severity": "info",
                        "category": "info",
                        "description": "Public key authentication is available (recommended).",
                        "evidence": f"Auth methods: {', '.join(auth_methods)}",
                    })
            except paramiko.AuthenticationException:
                pass
            finally:
                transport.close()
        except ImportError:
            pass
        except Exception as e:
            logger.debug("SSH auth check failed", error=str(e))

        return findings
