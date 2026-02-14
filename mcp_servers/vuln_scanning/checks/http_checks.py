import asyncio
import ssl
import structlog

logger = structlog.get_logger()

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "medium",
        "description": "HSTS forces browsers to use HTTPS, preventing protocol downgrade attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe_id": "CWE-319",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "description": "Prevents MIME-type sniffing which can lead to XSS attacks.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe_id": "CWE-693",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe_id": "CWE-1021",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "medium",
        "description": "CSP mitigates XSS and data injection attacks by controlling allowed resource sources.",
        "remediation": "Add a Content-Security-Policy header with appropriate directives.",
        "cwe_id": "CWE-693",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS filter. While deprecated, its absence may indicate lack of security awareness.",
        "remediation": "Add header: X-XSS-Protection: 0 (or rely on CSP instead)",
        "cwe_id": "CWE-79",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe_id": "CWE-200",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls browser features available to the page (camera, microphone, geolocation).",
        "remediation": "Add a Permissions-Policy header restricting unnecessary browser features.",
        "cwe_id": "CWE-693",
    },
}


class HTTPSecurityChecker:
    async def check(self, target: str, port: int = 80, use_tls: bool = False) -> list[dict]:
        logger.info("Starting HTTP security check", target=target, port=port, tls=use_tls)
        findings = []

        try:
            headers, server_header, status, raw_response = await self._fetch_headers(target, port, use_tls)
        except Exception as e:
            logger.warning("HTTP check failed", target=target, port=port, error=str(e))
            return [{
                "title": f"HTTP service on port {port} not responding",
                "severity": "info",
                "category": "info",
                "description": f"Could not connect to HTTP{'S' if use_tls else ''} service: {str(e)}",
                "evidence": str(e),
            }]

        # Check missing security headers
        for header_key, info in SECURITY_HEADERS.items():
            if header_key not in headers:
                # Only check HSTS for TLS services
                if header_key == "strict-transport-security" and not use_tls:
                    continue
                findings.append({
                    "title": f"Missing {info['name']} header",
                    "severity": info["severity"],
                    "category": "misconfig",
                    "description": info["description"],
                    "remediation": info["remediation"],
                    "cwe_id": info["cwe_id"],
                    "evidence": f"Header '{header_key}' not found in HTTP response from {target}:{port}",
                })

        # Check server header information disclosure
        if server_header:
            findings.append({
                "title": "Server header reveals software version",
                "severity": "low",
                "category": "info",
                "description": f"The Server header discloses: {server_header}. This helps attackers identify specific vulnerabilities.",
                "remediation": "Configure the web server to suppress or generalize the Server header.",
                "cwe_id": "CWE-200",
                "evidence": f"Server: {server_header}",
            })

        # Check for HTTP on admin-likely ports
        if not use_tls and port in (80, 8080, 8000):
            findings.append({
                "title": f"HTTP service without TLS on port {port}",
                "severity": "medium",
                "category": "misconfig",
                "description": "Service uses unencrypted HTTP. Credentials and data transmitted in cleartext.",
                "remediation": "Enable HTTPS/TLS and redirect HTTP to HTTPS.",
                "cwe_id": "CWE-319",
                "evidence": f"HTTP (no TLS) service detected on {target}:{port}",
            })

        logger.info("HTTP check complete", target=target, finding_count=len(findings))
        return findings

    async def _fetch_headers(self, target: str, port: int, use_tls: bool) -> tuple[dict, str | None, int, str]:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx), timeout=10
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=10
            )

        request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nUser-Agent: RiskPlatform/1.0\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        data = await asyncio.wait_for(reader.read(8192), timeout=10)
        response = data.decode("utf-8", errors="replace")
        writer.close()
        await writer.wait_closed()

        headers = {}
        server_header = None
        status_code = 0
        lines = response.split("\r\n")

        if lines:
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass

        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                key_lower = key.strip().lower()
                headers[key_lower] = value.strip()
                if key_lower == "server":
                    server_header = value.strip()

        return headers, server_header, status_code, response
