import asyncio
import ssl
import socket
from datetime import datetime
import structlog

logger = structlog.get_logger()

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
STRONG_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}


class TLSChecker:
    async def check(self, target: str, port: int = 443) -> list[dict]:
        logger.info("Starting TLS check", target=target, port=port)
        findings = []

        try:
            cert_info, protocol, cipher, raw = await self._get_tls_info(target, port)
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
            # Port not open or host unreachable — not a vulnerability
            logger.info("TLS port not reachable", target=target, port=port, error=str(e))
            return []
        except Exception as e:
            logger.warning("TLS check failed", target=target, port=port, error=str(e))
            err_str = str(e).lower()
            # SSL handshake failures on open ports are noteworthy but not high severity
            if "handshake" in err_str or "ssl" in err_str:
                return [{
                    "title": f"TLS handshake failed on port {port}",
                    "severity": "medium",
                    "category": "misconfig",
                    "description": f"TLS service on port {port} refused the handshake: {str(e)}",
                    "evidence": str(e),
                    "cwe_id": "CWE-319",
                }]
            return []

        # Check protocol version (exact match to avoid "TLSv1" matching "TLSv1.3")
        if protocol and protocol in WEAK_PROTOCOLS:
            findings.append({
                "title": f"Weak TLS protocol version: {protocol}",
                "severity": "high",
                "category": "vuln",
                "description": f"Server supports {protocol} which has known vulnerabilities. TLS 1.2 or 1.3 should be required.",
                "remediation": "Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2.",
                "cwe_id": "CWE-326",
                "evidence": f"Negotiated protocol: {protocol}",
            })
        elif protocol and protocol in STRONG_PROTOCOLS:
            findings.append({
                "title": f"TLS protocol version: {protocol}",
                "severity": "info",
                "category": "info",
                "description": f"Server uses {protocol}.",
                "evidence": f"Negotiated protocol: {protocol}",
            })
        elif protocol:
            findings.append({
                "title": f"Unknown TLS protocol version: {protocol}",
                "severity": "medium",
                "category": "misconfig",
                "description": f"Server negotiated {protocol} which is not a recognized strong protocol.",
                "evidence": f"Negotiated protocol: {protocol}",
            })

        # Check cipher strength
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            if any(weak in cipher_name.upper() for weak in WEAK_CIPHERS):
                findings.append({
                    "title": f"Weak cipher suite: {cipher_name}",
                    "severity": "high",
                    "category": "vuln",
                    "description": "Server uses a cipher suite with known weaknesses.",
                    "remediation": "Configure server to use strong cipher suites only (AES-GCM, ChaCha20-Poly1305).",
                    "cwe_id": "CWE-327",
                    "evidence": f"Negotiated cipher: {cipher_name}",
                })

        # Check certificate
        if cert_info:
            # Expiry check
            not_after = cert_info.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until = (expiry - datetime.utcnow()).days
                    if days_until < 0:
                        findings.append({
                            "title": "TLS certificate has expired",
                            "severity": "critical",
                            "category": "vuln",
                            "description": f"Certificate expired {abs(days_until)} days ago on {not_after}.",
                            "remediation": "Renew the TLS certificate immediately.",
                            "cwe_id": "CWE-298",
                            "evidence": f"Certificate notAfter: {not_after}",
                        })
                    elif days_until < 30:
                        findings.append({
                            "title": f"TLS certificate expires in {days_until} days",
                            "severity": "medium",
                            "category": "misconfig",
                            "description": f"Certificate expires on {not_after}. Renew soon to avoid service disruption.",
                            "remediation": "Renew the TLS certificate before expiration.",
                            "cwe_id": "CWE-298",
                            "evidence": f"Certificate notAfter: {not_after}, days remaining: {days_until}",
                        })
                except (ValueError, TypeError):
                    pass

            # Self-signed check
            issuer = cert_info.get("issuer", ())
            subject = cert_info.get("subject", ())
            if issuer and subject and issuer == subject:
                findings.append({
                    "title": "Self-signed TLS certificate",
                    "severity": "low",
                    "category": "misconfig",
                    "description": "Certificate is self-signed. While common for home devices, it prevents proper certificate validation.",
                    "remediation": "For internal services, consider using a local CA. For external, use Let's Encrypt.",
                    "cwe_id": "CWE-295",
                    "evidence": f"Issuer matches Subject: {issuer}",
                })

            # Subject info
            subject_cn = ""
            for rdn in subject:
                for attr in rdn:
                    if attr[0] == "commonName":
                        subject_cn = attr[1]
            if subject_cn:
                findings.append({
                    "title": f"TLS certificate subject: {subject_cn}",
                    "severity": "info",
                    "category": "info",
                    "description": f"Certificate issued for: {subject_cn}",
                    "evidence": f"Subject CN: {subject_cn}",
                })

        logger.info("TLS check complete", target=target, finding_count=len(findings))
        return findings

    async def _get_tls_info(self, target: str, port: int) -> tuple[dict, str, tuple, str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=ctx), timeout=10
        )

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False) if ssl_obj else {}
            protocol = ssl_obj.version() if ssl_obj else ""
            cipher = ssl_obj.cipher() if ssl_obj else ()
        finally:
            writer.close()
            await writer.wait_closed()

        raw = f"Protocol: {protocol}, Cipher: {cipher}, Cert: {cert}"
        return cert or {}, protocol or "", cipher or (), raw
