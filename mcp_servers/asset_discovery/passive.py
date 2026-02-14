import asyncio
import socket
import struct
from datetime import datetime
import structlog

logger = structlog.get_logger()


class PassiveDiscovery:
    async def mdns_discover(self, duration: int = 10) -> list[dict]:
        """Discover devices via mDNS (Bonjour/Avahi)."""
        logger.info("Starting mDNS discovery", duration=duration)
        services: list[dict] = []

        try:
            from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange

            discovered: list[dict] = []

            class MDNSListener:
                def __init__(self, zc: Zeroconf):
                    self.zc = zc

                def remove_service(self, zc, type_, name):
                    pass

                def update_service(self, zc, type_, name):
                    pass

                def add_service(self, zc, type_, name):
                    try:
                        info = zc.get_service_info(type_, name)
                        if info:
                            addresses = info.parsed_addresses()
                            ip = addresses[0] if addresses else None
                            discovered.append({
                                "name": name,
                                "type": type_,
                                "ip": ip,
                                "port": info.port,
                                "hostname": info.server,
                                "properties": {
                                    k.decode() if isinstance(k, bytes) else k:
                                    v.decode() if isinstance(v, bytes) else str(v)
                                    for k, v in (info.properties or {}).items()
                                },
                            })
                    except Exception as e:
                        logger.debug("mDNS service info failed", name=name, error=str(e))

            zc = Zeroconf()

            service_types = [
                "_http._tcp.local.",
                "_https._tcp.local.",
                "_ssh._tcp.local.",
                "_smb._tcp.local.",
                "_ftp._tcp.local.",
                "_printer._tcp.local.",
                "_ipp._tcp.local.",
                "_airplay._tcp.local.",
                "_raop._tcp.local.",
                "_googlecast._tcp.local.",
                "_spotify-connect._tcp.local.",
                "_sonos._tcp.local.",
                "_hap._tcp.local.",
                "_hue._tcp.local.",
                "_mqtt._tcp.local.",
                "_coap._udp.local.",
            ]

            listener = MDNSListener(zc)
            browsers = []
            for stype in service_types:
                try:
                    browser = ServiceBrowser(zc, stype, listener)
                    browsers.append(browser)
                except Exception:
                    pass

            await asyncio.sleep(duration)

            zc.close()
            services = discovered

        except ImportError:
            logger.warning("zeroconf not installed, mDNS discovery unavailable")
        except Exception as e:
            logger.error("mDNS discovery failed", error=str(e))

        logger.info("mDNS discovery complete", services_found=len(services))
        return services

    async def ssdp_discover(self, timeout: int = 5) -> list[dict]:
        """Discover UPnP devices via SSDP M-SEARCH."""
        logger.info("Starting SSDP discovery", timeout=timeout)
        devices: list[dict] = []

        try:
            loop = asyncio.get_event_loop()
            devices = await loop.run_in_executor(None, self._ssdp_search, timeout)
        except Exception as e:
            logger.error("SSDP discovery failed", error=str(e))

        logger.info("SSDP discovery complete", devices_found=len(devices))
        return devices

    def _ssdp_search(self, timeout: int) -> list[dict]:
        """Perform SSDP M-SEARCH (synchronous)."""
        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900

        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
        except OSError as e:
            logger.warning("SSDP send failed", error=str(e))
            sock.close()
            return []

        devices: list[dict] = []
        seen_locations: set[str] = set()

        try:
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode("utf-8", errors="ignore")

                    headers: dict[str, str] = {}
                    for line in response.split("\r\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            headers[key.strip().upper()] = value.strip()

                    location = headers.get("LOCATION", "")
                    if location and location not in seen_locations:
                        seen_locations.add(location)
                        devices.append({
                            "ip": addr[0],
                            "port": addr[1],
                            "location": location,
                            "server": headers.get("SERVER", ""),
                            "st": headers.get("ST", ""),
                            "usn": headers.get("USN", ""),
                        })

                except socket.timeout:
                    break
                except Exception:
                    break
        finally:
            sock.close()

        return devices
