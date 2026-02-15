import asyncio
import ssl
import struct
import structlog

logger = structlog.get_logger()


class MQTTChecker:
    async def check(self, target: str, port: int = 1883, timeout: int = 10) -> list[dict]:
        logger.info("Starting MQTT check", target=target, port=port)
        findings = []

        # Check plaintext MQTT (port 1883)
        if port == 1883:
            anon_access = await self._check_anonymous(target, 1883, use_tls=False, timeout=timeout)
            if anon_access:
                findings.append({
                    "title": f"MQTT broker allows anonymous access on {target}:1883",
                    "severity": "high",
                    "category": "vuln",
                    "description": (
                        f"The MQTT broker on {target}:1883 accepts connections without credentials. "
                        f"This allows any client to publish and subscribe to topics, potentially "
                        f"controlling IoT devices or accessing sensitive sensor data."
                    ),
                    "remediation": (
                        "Configure MQTT broker to require authentication. "
                        "Use TLS (port 8883) for encrypted communication. "
                        "Set up ACLs to restrict topic access per client."
                    ),
                    "cwe_id": "CWE-287",
                    "evidence": f"MQTT CONNECT without credentials accepted (CONNACK return code 0) on {target}:1883",
                })

                # If anonymous access works, try subscribing to $SYS
                sys_info = await self._check_sys_topics(target, 1883, use_tls=False, timeout=timeout)
                if sys_info:
                    findings.append({
                        "title": f"MQTT $SYS topic information disclosure on {target}:1883",
                        "severity": "medium",
                        "category": "exposure",
                        "description": (
                            f"The MQTT broker on {target}:1883 exposes $SYS/# system topics to anonymous clients. "
                            f"This reveals broker version, uptime, client count, and other operational details."
                        ),
                        "remediation": (
                            "Restrict access to $SYS/# topics. "
                            "Configure ACLs to limit which clients can subscribe to system topics."
                        ),
                        "cwe_id": "CWE-200",
                        "evidence": f"$SYS topic data received: {sys_info[:200]}",
                    })

            # Check for plaintext communication
            plaintext = await self._check_port_open(target, 1883, timeout)
            if plaintext and not any(f["severity"] in ("high", "critical") for f in findings):
                findings.append({
                    "title": f"MQTT broker using plaintext on {target}:1883",
                    "severity": "medium",
                    "category": "misconfig",
                    "description": (
                        f"MQTT broker on {target} is accessible over plaintext (port 1883). "
                        f"Credentials and messages are transmitted without encryption."
                    ),
                    "remediation": "Configure MQTT broker to use TLS on port 8883. Disable plaintext listener.",
                    "cwe_id": "CWE-319",
                    "evidence": f"MQTT plaintext service responding on {target}:1883",
                })

        # Check MQTTS (port 8883)
        if port == 8883:
            mqtts_anon = await self._check_anonymous(target, 8883, use_tls=True, timeout=timeout)
            if mqtts_anon:
                findings.append({
                    "title": f"MQTT broker allows anonymous access on {target}:8883 (TLS)",
                    "severity": "high",
                    "category": "vuln",
                    "description": (
                        f"The MQTT broker on {target}:8883 (TLS) accepts connections without credentials. "
                        f"While TLS protects the transport, anonymous access still allows unauthorized control."
                    ),
                    "remediation": "Require client authentication (username/password or client certificates).",
                    "cwe_id": "CWE-287",
                    "evidence": f"MQTT CONNECT without credentials accepted on {target}:8883 (TLS)",
                })

        if not findings:
            findings.append({
                "title": f"MQTT check on {target}:{port}",
                "severity": "info",
                "category": "info",
                "description": f"MQTT service on {target}:{port} did not allow anonymous access or was not reachable.",
                "evidence": f"No anonymous access on {target}:{port}",
            })

        logger.info("MQTT check complete", target=target, finding_count=len(findings))
        return findings

    async def _check_anonymous(self, target: str, port: int, use_tls: bool, timeout: int) -> bool:
        """Try connecting to MQTT broker without credentials."""
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

            # Build MQTT CONNECT packet (no username/password)
            connect_packet = self._build_connect_packet()
            writer.write(connect_packet)
            await writer.drain()

            # Read CONNACK response
            response = await asyncio.wait_for(reader.read(256), timeout=timeout)
            writer.close()
            await writer.wait_closed()

            if response and len(response) >= 4:
                # CONNACK: byte 0 = 0x20, byte 1 = remaining length (2)
                # byte 3 = return code (0 = accepted)
                if response[0] == 0x20 and response[3] == 0x00:
                    return True

            return False
        except Exception:
            return False

    async def _check_sys_topics(self, target: str, port: int, use_tls: bool, timeout: int) -> str | None:
        """Try subscribing to $SYS/# topics."""
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

            # CONNECT
            writer.write(self._build_connect_packet())
            await writer.drain()
            connack = await asyncio.wait_for(reader.read(256), timeout=5)
            if not connack or len(connack) < 4 or connack[3] != 0x00:
                writer.close()
                await writer.wait_closed()
                return None

            # SUBSCRIBE to $SYS/#
            subscribe_packet = self._build_subscribe_packet("$SYS/#")
            writer.write(subscribe_packet)
            await writer.drain()

            # Wait for any PUBLISH messages
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                if data and len(data) > 5:
                    # Try to extract readable content
                    text = data.decode("utf-8", errors="replace")
                    writer.close()
                    await writer.wait_closed()
                    return text
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
            return None
        except Exception:
            return None

    async def _check_port_open(self, target: str, port: int, timeout: int) -> bool:
        """Quick port check."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=3,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def _build_connect_packet(self) -> bytes:
        """Build MQTT v3.1.1 CONNECT packet without credentials."""
        # Variable header
        protocol_name = b"\x00\x04MQTT"
        protocol_level = b"\x04"  # MQTT 3.1.1
        connect_flags = b"\x02"   # Clean session, no credentials
        keep_alive = b"\x00\x3c"  # 60 seconds

        # Payload: Client ID
        client_id = b"vuln_scanner"
        client_id_field = struct.pack("!H", len(client_id)) + client_id

        variable_header = protocol_name + protocol_level + connect_flags + keep_alive
        payload = client_id_field

        remaining = variable_header + payload
        remaining_length = len(remaining)

        # Fixed header: CONNECT = 0x10
        packet = b"\x10" + self._encode_remaining_length(remaining_length) + remaining
        return packet

    def _build_subscribe_packet(self, topic: str) -> bytes:
        """Build MQTT SUBSCRIBE packet."""
        # Packet identifier
        packet_id = b"\x00\x01"
        # Topic filter
        topic_bytes = topic.encode()
        topic_field = struct.pack("!H", len(topic_bytes)) + topic_bytes
        qos = b"\x00"  # QoS 0

        payload = topic_field + qos
        remaining = packet_id + payload
        remaining_length = len(remaining)

        # Fixed header: SUBSCRIBE = 0x82
        packet = b"\x82" + self._encode_remaining_length(remaining_length) + remaining
        return packet

    def _encode_remaining_length(self, length: int) -> bytes:
        """Encode MQTT remaining length field."""
        encoded = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length == 0:
                break
        return bytes(encoded)
