"""Rule-based threat generation engine."""
from mcp_servers.threat_modeling.catalogs import (
    HOME_THREAT_CATALOG,
    ZONE_THREAT_CATALOG,
    TRUST_BOUNDARY_THREATS,
)
import structlog

logger = structlog.get_logger()


class ThreatRuleEngine:
    def evaluate(self, asset: dict) -> list[dict]:
        """Generate threats for a specific asset based on its properties."""
        threats = []
        asset_type = asset.get("asset_type", "unknown")
        zone = asset.get("zone", "lan")
        exposure = asset.get("exposure", {})
        open_ports = set(asset.get("open_ports", []))
        services = set(asset.get("services", []))
        criticality = asset.get("criticality", "medium")

        # 1. Apply catalog threats for asset type
        catalog_threats = HOME_THREAT_CATALOG.get(asset_type, [])
        for threat in catalog_threats:
            t = {**threat, "source": "rule", "zone": zone}
            # Adjust confidence based on zone trust level
            if zone == "iot":
                t["confidence"] = min(1.0, t["confidence"] + 0.1)
            elif zone == "dmz":
                t["confidence"] = min(1.0, t["confidence"] + 0.1)
            threats.append(t)

        # 2. Service-specific threats
        threats.extend(self._service_threats(open_ports, services, zone, asset_type))

        # 3. Exposure-based threats
        threats.extend(self._exposure_threats(exposure, zone, asset_type))

        # 4. Adjust confidence based on criticality
        crit_boost = {"critical": 0.15, "high": 0.1, "medium": 0.0, "low": -0.1}
        boost = crit_boost.get(criticality, 0.0)
        for t in threats:
            t["confidence"] = max(0.1, min(1.0, t["confidence"] + boost))

        # Deduplicate by title
        seen = set()
        unique = []
        for t in threats:
            if t["title"] not in seen:
                seen.add(t["title"])
                unique.append(t)

        logger.info("Threats generated", asset_type=asset_type, zone=zone, count=len(unique))
        return unique

    def _service_threats(self, open_ports: set, services: set, zone: str, asset_type: str) -> list[dict]:
        threats = []

        if 23 in open_ports:
            threats.append({
                "title": "Telnet service enabled (cleartext protocol)",
                "threat_type": "information_disclosure",
                "description": "Telnet transmits all data including credentials in cleartext. Should be replaced with SSH.",
                "confidence": 0.9,
                "source": "rule",
                "zone": zone,
            })

        if 21 in open_ports:
            threats.append({
                "title": "FTP service enabled (cleartext protocol)",
                "threat_type": "information_disclosure",
                "description": "FTP transmits credentials and data in cleartext. Should use SFTP or FTPS.",
                "confidence": 0.8,
                "source": "rule",
                "zone": zone,
            })

        if 80 in open_ports and asset_type in ("router", "nas", "camera"):
            threats.append({
                "title": f"HTTP admin interface without TLS on {asset_type}",
                "threat_type": "information_disclosure",
                "description": "Admin credentials transmitted over unencrypted HTTP connection.",
                "confidence": 0.8,
                "source": "rule",
                "zone": zone,
            })

        if 161 in open_ports:
            threats.append({
                "title": "SNMP service exposed",
                "threat_type": "information_disclosure",
                "description": "SNMP v1/v2c uses community strings in cleartext. May expose device configuration.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        if 445 in open_ports and zone in ("iot", "guest"):
            threats.append({
                "title": "SMB service exposed in untrusted zone",
                "threat_type": "elevation_of_privilege",
                "description": "SMB service accessible from untrusted network zone increases attack surface.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        if 3389 in open_ports:
            threats.append({
                "title": "RDP service exposed",
                "threat_type": "spoofing",
                "description": "Remote Desktop Protocol is a common target for brute-force attacks.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        if 5900 in open_ports:
            threats.append({
                "title": "VNC service exposed",
                "threat_type": "spoofing",
                "description": "VNC may use weak authentication and transmit screen data with weak encryption.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        db_ports = open_ports & {3306, 5432, 6379, 27017, 1433, 9200}
        if db_ports:
            threats.append({
                "title": f"Database service exposed on ports {sorted(db_ports)}",
                "threat_type": "information_disclosure",
                "description": "Database services accessible on the network risk unauthorized data access or data exfiltration.",
                "confidence": 0.6,
                "source": "rule",
                "zone": zone,
            })

        if 1883 in open_ports:
            threats.append({
                "title": "MQTT broker without TLS",
                "threat_type": "information_disclosure",
                "description": "MQTT messages transmitted in cleartext. IoT sensor data and commands exposed.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        return threats

    def _exposure_threats(self, exposure: dict, zone: str, asset_type: str) -> list[dict]:
        threats = []

        if exposure.get("upnp"):
            threats.append({
                "title": "UPnP enabled on device",
                "threat_type": "tampering",
                "description": "UPnP allows automatic port forwarding, potentially exposing internal services to the internet.",
                "confidence": 0.8,
                "source": "rule",
                "zone": zone,
            })

        if exposure.get("admin_ui") and zone in ("iot", "guest"):
            threats.append({
                "title": "Admin interface accessible from untrusted zone",
                "threat_type": "elevation_of_privilege",
                "description": f"Device admin interface in {zone} zone accessible to untrusted devices.",
                "confidence": 0.7,
                "source": "rule",
                "zone": zone,
            })

        if exposure.get("wan_accessible"):
            threats.append({
                "title": "Service directly accessible from the internet",
                "threat_type": "elevation_of_privilege",
                "description": "Internet-accessible services are subject to automated scanning and exploitation attempts.",
                "confidence": 0.9,
                "source": "rule",
                "zone": zone,
            })

        if exposure.get("telnet_exposed"):
            threats.append({
                "title": "Telnet exposed - cleartext remote access",
                "threat_type": "information_disclosure",
                "description": "Telnet provides unencrypted remote shell access. Common IoT botnet entry vector.",
                "confidence": 0.9,
                "source": "rule",
                "zone": zone,
            })

        return threats

    def evaluate_zone(self, zone: str, asset_count: int, asset_types: list[str], has_isolation: bool) -> list[dict]:
        """Generate zone-level threats."""
        threats = []

        # Catalog zone threats
        for t in ZONE_THREAT_CATALOG.get(zone, []):
            threat = {**t, "source": "rule", "zone": zone}
            # If isolated, reduce confidence
            if has_isolation and "isolation" in t.get("title", "").lower():
                threat["confidence"] = max(0.1, threat["confidence"] - 0.4)
            threats.append(threat)

        # Mixed trust level threat
        if len(set(asset_types)) > 2 and not has_isolation:
            threats.append({
                "title": f"Mixed device types in {zone} zone without segmentation",
                "threat_type": "elevation_of_privilege",
                "description": f"Zone '{zone}' contains {len(set(asset_types))} different device types ({', '.join(set(asset_types))}) without network segmentation.",
                "confidence": 0.6,
                "source": "rule",
                "zone": zone,
            })

        # High density threat
        if asset_count > 20:
            threats.append({
                "title": f"High device density in {zone} zone ({asset_count} devices)",
                "threat_type": "denial_of_service",
                "description": "Large number of devices in a single zone increases broadcast traffic and attack surface.",
                "confidence": 0.4,
                "source": "rule",
                "zone": zone,
            })

        return threats

    def evaluate_trust_boundary(self, from_zone: str, to_zone: str, services: list[str], controls: list[str]) -> list[dict]:
        """Generate threats for trust boundary crossings."""
        threats = []

        # Catalog boundary threats
        key = (from_zone, to_zone)
        reverse_key = (to_zone, from_zone)

        for t in TRUST_BOUNDARY_THREATS.get(key, []):
            threat = {**t, "source": "rule", "trust_boundary": f"{from_zone} -> {to_zone}"}
            threats.append(threat)

        for t in TRUST_BOUNDARY_THREATS.get(reverse_key, []):
            threat = {**t, "source": "rule", "trust_boundary": f"{to_zone} -> {from_zone}"}
            threats.append(threat)

        # Missing controls
        if not controls:
            threats.append({
                "title": f"No security controls between {from_zone} and {to_zone}",
                "threat_type": "elevation_of_privilege",
                "description": f"Traffic between {from_zone} and {to_zone} zones is uncontrolled.",
                "confidence": 0.8,
                "source": "rule",
                "trust_boundary": f"{from_zone} -> {to_zone}",
            })

        if services and "firewall" not in controls and "firewall_rules" not in controls:
            threats.append({
                "title": f"Services crossing {from_zone}-{to_zone} boundary without firewall",
                "threat_type": "tampering",
                "description": f"Services ({', '.join(services)}) cross trust boundary without firewall inspection.",
                "confidence": 0.7,
                "source": "rule",
                "trust_boundary": f"{from_zone} -> {to_zone}",
            })

        return threats
