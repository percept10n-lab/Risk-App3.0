import asyncio
import ssl
import structlog

logger = structlog.get_logger()

# Credential lists organized by device type
DEVICE_CREDENTIALS = {
    "router": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
    ],
    "camera": [
        ("admin", "12345"),
        ("root", "root"),
        ("admin", "admin"),
    ],
    "nas": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "password"),
    ],
    "generic": [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
    ],
}

MAX_ATTEMPTS = 3


class DefaultCredsChecker:
    async def check(self, target: str, port: int = 80, timeout: int = 10,
                    device_type: str = "generic") -> list[dict]:
        logger.info("Starting default credentials check", target=target, port=port, device_type=device_type)
        findings = []

        use_tls = port in (443, 8443, 4443)
        creds = DEVICE_CREDENTIALS.get(device_type, DEVICE_CREDENTIALS["generic"])

        # First check if there's a login page / HTTP service
        has_http = await self._check_http_service(target, port, use_tls, timeout)
        if not has_http:
            return findings

        # Try credentials (max 3 to avoid lockout)
        for username, password in creds[:MAX_ATTEMPTS]:
            try:
                success = await asyncio.wait_for(
                    self._try_credential(target, port, username, password, use_tls),
                    timeout=timeout,
                )
                if success:
                    findings.append({
                        "title": f"Default credentials accepted on {target}:{port}",
                        "severity": "critical",
                        "category": "vuln",
                        "description": (
                            f"The web interface on {target}:{port} accepts default credentials "
                            f"(username: '{username}'). This allows unauthorized administrative access."
                        ),
                        "remediation": (
                            "Change the default credentials immediately. "
                            "Use a strong, unique password for the device admin interface."
                        ),
                        "cwe_id": "CWE-798",
                        "evidence": f"HTTP authentication with {username}/***** accepted on {target}:{port}",
                    })
                    # Stop after first successful login
                    break
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug("Credential check failed", target=target, username=username, error=str(e))

        logger.info("Default credentials check complete", target=target, finding_count=len(findings))
        return findings

    async def _check_http_service(self, target: str, port: int, use_tls: bool, timeout: int) -> bool:
        """Check if HTTP service is responding."""
        try:
            if use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ssl_ctx),
                    timeout=5,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=5,
                )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _try_credential(self, target: str, port: int,
                              username: str, password: str, use_tls: bool) -> bool:
        """Try Basic Auth credentials against HTTP service."""
        import base64

        auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}:{port}\r\n"
            f"Authorization: Basic {auth_string}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        writer = None
        try:
            if use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ssl_ctx),
                    timeout=5,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=5,
                )

            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(2048), timeout=5)

            response_str = response.decode("utf-8", errors="replace")
            first_line = response_str.split("\r\n")[0] if response_str else ""

            if "200" in first_line:
                no_auth_status = await self._check_without_auth(target, port, use_tls)
                if no_auth_status == 401 or no_auth_status == 403:
                    return True

            return False
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def _check_without_auth(self, target: str, port: int, use_tls: bool) -> int:
        """Send request without auth to check if auth is required."""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}:{port}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer = None
        try:
            if use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port, ssl=ssl_ctx),
                    timeout=5,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=5,
                )

            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=5)

            first_line = response.decode("utf-8", errors="replace").split("\r\n")[0]
            if "401" in first_line:
                return 401
            if "403" in first_line:
                return 403
            if "200" in first_line:
                return 200
            return 0
        except Exception:
            return 0
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
