"""Predefined test scenarios for eval harness regression testing.

Each scenario is a self-contained dict with mock input data and expected
output, designed for home-network risk-assessment pipelines.
"""

import structlog

logger = structlog.get_logger()

SCENARIOS: list[dict] = [
    # ------------------------------------------------------------------
    # Scenario 1: basic_router
    # ------------------------------------------------------------------
    {
        "id": "basic_router",
        "name": "Router with open admin, UPnP, and SSH password auth",
        "description": (
            "Tests detection of common router misconfigurations: HTTP admin "
            "without TLS, UPnP enabled, SSH with password authentication, "
            "and outdated firmware.  Expects multiple high/critical risks "
            "and relevant MITRE ATT&CK mappings."
        ),
        "input": {
            "assets": [
                {
                    "ip_address": "192.168.1.1",
                    "hostname": "home-router",
                    "asset_type": "router",
                    "criticality": "critical",
                    "zone": "lan",
                    "open_ports": [22, 80, 443, 1900, 5000],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.4"},
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "lighttpd/1.4.35"},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": "lighttpd/1.4.35"},
                        {"port": 1900, "protocol": "udp", "service": "upnp", "version": ""},
                        {"port": 5000, "protocol": "tcp", "service": "http", "version": "admin-panel"},
                    ],
                    "os_guess": "Linux 3.10",
                    "vendor": "Netgear",
                },
            ],
            "findings": [
                {
                    "id": "F-BR-001",
                    "title": "HTTP admin panel without TLS",
                    "description": "Router admin panel on port 5000 served over plain HTTP, exposing credentials in transit.",
                    "severity": "high",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_tls",
                    "evidence": "GET http://192.168.1.1:5000/ returns 200 OK with login form; no HTTPS redirect.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Enable HTTPS on the admin panel and redirect HTTP to HTTPS.",
                    "asset_ip": "192.168.1.1",
                },
                {
                    "id": "F-BR-002",
                    "title": "UPnP enabled on LAN gateway",
                    "description": "Universal Plug and Play is active on the router, allowing any LAN device to open arbitrary port forwards.",
                    "severity": "high",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "upnp_enabled",
                    "evidence": "SSDP M-SEARCH response received from 192.168.1.1:1900 advertising rootdevice.",
                    "cve_ids": [],
                    "cwe_id": "CWE-284",
                    "remediation": "Disable UPnP in router settings.",
                    "asset_ip": "192.168.1.1",
                },
                {
                    "id": "F-BR-003",
                    "title": "SSH password authentication enabled",
                    "description": "SSH daemon accepts password-based logins, susceptible to brute-force attacks.",
                    "severity": "high",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "ssh_password_auth",
                    "evidence": "ssh -o PreferredAuthentications=password 192.168.1.1 prompts for password.",
                    "cve_ids": [],
                    "cwe_id": "CWE-307",
                    "remediation": "Disable PasswordAuthentication in sshd_config and use key-based auth.",
                    "asset_ip": "192.168.1.1",
                },
                {
                    "id": "F-BR-004",
                    "title": "Outdated firmware detected",
                    "description": "Router firmware version is 2 major releases behind current, missing critical security patches.",
                    "severity": "critical",
                    "category": "vuln",
                    "source_tool": "fingerprinting",
                    "source_check": "firmware_version",
                    "evidence": "Firmware header: Netgear R7000 V1.0.9.88; latest stable is V1.0.11.134.",
                    "cve_ids": ["CVE-2021-45388", "CVE-2022-27646"],
                    "cwe_id": "CWE-1104",
                    "remediation": "Update firmware to the latest stable release from the vendor.",
                    "asset_ip": "192.168.1.1",
                },
            ],
            "threats": [
                {
                    "title": "Credential theft via unencrypted admin channel",
                    "threat_type": "credential_access",
                    "confidence": 0.9,
                    "description": "Attacker on the LAN sniffs plain-HTTP admin credentials.",
                },
                {
                    "title": "Arbitrary port-forward abuse via UPnP",
                    "threat_type": "initial_access",
                    "confidence": 0.85,
                    "description": "Malware on a LAN device uses UPnP to expose internal services to the internet.",
                },
            ],
        },
        "expected_output": {
            "min_high_critical_count": 3,
            "required_mitre_ids": ["T1078", "T1133"],
            "risk_levels_present": ["high", "critical"],
            "expected_risk_range": {"min": "high", "max": "critical"},
            "finding_count": 4,
        },
        "tags": ["router", "misconfig", "credential", "firmware", "regression"],
    },

    # ------------------------------------------------------------------
    # Scenario 2: iot_camera
    # ------------------------------------------------------------------
    {
        "id": "iot_camera",
        "name": "IoT camera with weak security",
        "description": (
            "Tests detection of IoT-specific weaknesses: default credentials, "
            "open RTSP stream, no TLS, and telnet enabled.  Expects critical "
            "risk with MITRE mappings for T1078 and T1021."
        ),
        "input": {
            "assets": [
                {
                    "ip_address": "192.168.1.50",
                    "hostname": "cam-backyard",
                    "asset_type": "camera",
                    "criticality": "medium",
                    "zone": "iot",
                    "open_ports": [23, 80, 554, 8080],
                    "services": [
                        {"port": 23, "protocol": "tcp", "service": "telnet", "version": ""},
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "GoAhead-Webs"},
                        {"port": 554, "protocol": "tcp", "service": "rtsp", "version": ""},
                        {"port": 8080, "protocol": "tcp", "service": "http-alt", "version": ""},
                    ],
                    "os_guess": "Linux 2.6 embedded",
                    "vendor": "Hikvision",
                },
            ],
            "findings": [
                {
                    "id": "F-IC-001",
                    "title": "Default credentials active",
                    "description": "Camera admin interface accepts factory-default username/password (admin:admin).",
                    "severity": "critical",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "default_credentials",
                    "evidence": "HTTP POST to /login with admin:admin returns 200 OK and session cookie.",
                    "cve_ids": [],
                    "cwe_id": "CWE-798",
                    "remediation": "Change default credentials immediately.",
                    "asset_ip": "192.168.1.50",
                },
                {
                    "id": "F-IC-002",
                    "title": "RTSP stream unauthenticated",
                    "description": "RTSP video feed on port 554 is accessible without any credentials.",
                    "severity": "high",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "rtsp_open",
                    "evidence": "ffprobe rtsp://192.168.1.50:554/stream1 returns valid SDP without authentication challenge.",
                    "cve_ids": [],
                    "cwe_id": "CWE-306",
                    "remediation": "Require RTSP authentication and restrict to trusted clients.",
                    "asset_ip": "192.168.1.50",
                },
                {
                    "id": "F-IC-003",
                    "title": "Web interface served over plain HTTP",
                    "description": "Camera web UI on port 80 and 8080 does not support TLS.",
                    "severity": "high",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_tls",
                    "evidence": "Connection to ports 80 and 8080 return HTTP responses; no TLS handshake.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Enable HTTPS if supported by firmware, or isolate the device on a VLAN.",
                    "asset_ip": "192.168.1.50",
                },
                {
                    "id": "F-IC-004",
                    "title": "Telnet service enabled",
                    "description": "Telnet daemon on port 23 provides unencrypted remote shell access.",
                    "severity": "critical",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "telnet_enabled",
                    "evidence": "telnet 192.168.1.50 returns login prompt with banner 'BusyBox v1.20.2'.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Disable telnet; use SSH if remote access is needed.",
                    "asset_ip": "192.168.1.50",
                },
            ],
            "threats": [
                {
                    "title": "Unauthorized camera access via default credentials",
                    "threat_type": "credential_access",
                    "confidence": 0.95,
                    "description": "Attacker uses well-known default credentials to take over the camera.",
                },
                {
                    "title": "Lateral movement via telnet shell",
                    "threat_type": "lateral_movement",
                    "confidence": 0.8,
                    "description": "Attacker uses telnet access on the camera to pivot deeper into the network.",
                },
            ],
        },
        "expected_output": {
            "min_high_critical_count": 3,
            "required_mitre_ids": ["T1078", "T1021"],
            "risk_levels_present": ["high", "critical"],
            "expected_risk_range": {"min": "high", "max": "critical"},
            "finding_count": 4,
        },
        "tags": ["iot", "camera", "default_creds", "telnet", "regression"],
    },

    # ------------------------------------------------------------------
    # Scenario 3: secure_nas
    # ------------------------------------------------------------------
    {
        "id": "secure_nas",
        "name": "Well-configured NAS appliance",
        "description": (
            "Tests that a properly hardened NAS produces only low/info findings "
            "and no false-positive high/critical results.  Validates the pipeline "
            "does not over-report risk on well-secured devices."
        ),
        "input": {
            "assets": [
                {
                    "ip_address": "192.168.1.10",
                    "hostname": "nas-primary",
                    "asset_type": "nas",
                    "criticality": "high",
                    "zone": "lan",
                    "open_ports": [22, 443, 5001],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.3"},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx/1.24"},
                        {"port": 5001, "protocol": "tcp", "service": "https", "version": "Synology DSM"},
                    ],
                    "os_guess": "Linux 5.10 (Synology DSM 7.2)",
                    "vendor": "Synology",
                },
            ],
            "findings": [
                {
                    "id": "F-SN-001",
                    "title": "TLS 1.3 enabled on all HTTPS services",
                    "description": "All HTTPS endpoints negotiate TLS 1.3 with strong cipher suites.",
                    "severity": "info",
                    "category": "info",
                    "source_tool": "vuln_scanner",
                    "source_check": "tls_version",
                    "evidence": "TLS handshake on ports 443, 5001 negotiated TLS 1.3 (TLS_AES_256_GCM_SHA384).",
                    "cve_ids": [],
                    "cwe_id": None,
                    "remediation": None,
                    "asset_ip": "192.168.1.10",
                },
                {
                    "id": "F-SN-002",
                    "title": "SSH key-only authentication",
                    "description": "SSH daemon only allows public-key authentication; password auth is disabled.",
                    "severity": "info",
                    "category": "info",
                    "source_tool": "vuln_scanner",
                    "source_check": "ssh_auth_methods",
                    "evidence": "ssh -o PreferredAuthentications=password 192.168.1.10 returns 'Permission denied'.",
                    "cve_ids": [],
                    "cwe_id": None,
                    "remediation": None,
                    "asset_ip": "192.168.1.10",
                },
                {
                    "id": "F-SN-003",
                    "title": "Self-signed TLS certificate",
                    "description": "HTTPS services use a self-signed certificate not trusted by browsers.",
                    "severity": "low",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "tls_cert_trust",
                    "evidence": "Certificate issuer CN=Synology Inc. CA is not in the system trust store.",
                    "cve_ids": [],
                    "cwe_id": "CWE-295",
                    "remediation": "Install a certificate from a trusted CA or configure Let's Encrypt.",
                    "asset_ip": "192.168.1.10",
                },
            ],
            "threats": [],
        },
        "expected_output": {
            "min_high_critical_count": 0,
            "max_high_critical_count": 0,
            "required_mitre_ids": [],
            "risk_levels_present": ["info", "low"],
            "expected_risk_range": {"min": "info", "max": "low"},
            "finding_count": 3,
        },
        "tags": ["nas", "hardened", "false_positive_check", "regression"],
    },

    # ------------------------------------------------------------------
    # Scenario 4: mixed_network
    # ------------------------------------------------------------------
    {
        "id": "mixed_network",
        "name": "Mixed network with varying security postures",
        "description": (
            "Tests a realistic mixed home network: a router, a NAS, two "
            "workstations, and three IoT devices.  Expects a distribution "
            "of risk levels and zone-specific threat identification."
        ),
        "input": {
            "assets": [
                {
                    "ip_address": "192.168.1.1",
                    "hostname": "home-router",
                    "asset_type": "router",
                    "criticality": "critical",
                    "zone": "lan",
                    "open_ports": [22, 80, 443],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.9"},
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "lighttpd/1.4.59"},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": "lighttpd/1.4.59"},
                    ],
                    "os_guess": "Linux 5.4",
                    "vendor": "Asus",
                },
                {
                    "ip_address": "192.168.1.10",
                    "hostname": "nas-media",
                    "asset_type": "nas",
                    "criticality": "high",
                    "zone": "lan",
                    "open_ports": [22, 443, 5001, 8096],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.3"},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": "nginx/1.24"},
                        {"port": 5001, "protocol": "tcp", "service": "https", "version": "Synology DSM"},
                        {"port": 8096, "protocol": "tcp", "service": "http", "version": "Jellyfin 10.8"},
                    ],
                    "os_guess": "Linux 5.10",
                    "vendor": "Synology",
                },
                {
                    "ip_address": "192.168.1.100",
                    "hostname": "desktop-main",
                    "asset_type": "workstation",
                    "criticality": "medium",
                    "zone": "lan",
                    "open_ports": [22, 3389],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.0"},
                        {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "version": ""},
                    ],
                    "os_guess": "Windows 11",
                    "vendor": "Dell",
                },
                {
                    "ip_address": "192.168.1.101",
                    "hostname": "laptop-work",
                    "asset_type": "workstation",
                    "criticality": "medium",
                    "zone": "lan",
                    "open_ports": [22],
                    "services": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.5"},
                    ],
                    "os_guess": "macOS 14",
                    "vendor": "Apple",
                },
                {
                    "ip_address": "192.168.1.50",
                    "hostname": "cam-front",
                    "asset_type": "camera",
                    "criticality": "low",
                    "zone": "iot",
                    "open_ports": [80, 554],
                    "services": [
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "GoAhead-Webs"},
                        {"port": 554, "protocol": "tcp", "service": "rtsp", "version": ""},
                    ],
                    "os_guess": "Linux 2.6 embedded",
                    "vendor": "Reolink",
                },
                {
                    "ip_address": "192.168.1.51",
                    "hostname": "smart-thermostat",
                    "asset_type": "thermostat",
                    "criticality": "low",
                    "zone": "iot",
                    "open_ports": [80, 443],
                    "services": [
                        {"port": 80, "protocol": "tcp", "service": "http", "version": ""},
                        {"port": 443, "protocol": "tcp", "service": "https", "version": ""},
                    ],
                    "os_guess": "RTOS",
                    "vendor": "Ecobee",
                },
                {
                    "ip_address": "192.168.1.52",
                    "hostname": "smart-plug-01",
                    "asset_type": "smart_plug",
                    "criticality": "low",
                    "zone": "iot",
                    "open_ports": [80],
                    "services": [
                        {"port": 80, "protocol": "tcp", "service": "http", "version": ""},
                    ],
                    "os_guess": "RTOS",
                    "vendor": "TP-Link",
                },
            ],
            "findings": [
                {
                    "id": "F-MN-001",
                    "title": "HTTP admin without HTTPS redirect on router",
                    "description": "Router admin on port 80 does not redirect to HTTPS.",
                    "severity": "medium",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_redirect",
                    "evidence": "GET http://192.168.1.1/ returns 200 OK with login page; no 301/302 to HTTPS.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Configure HTTP-to-HTTPS redirect on the router admin interface.",
                    "asset_ip": "192.168.1.1",
                },
                {
                    "id": "F-MN-002",
                    "title": "Jellyfin media server over plain HTTP",
                    "description": "Jellyfin on port 8096 is served over unencrypted HTTP.",
                    "severity": "medium",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_tls",
                    "evidence": "GET http://192.168.1.10:8096/ returns Jellyfin web UI over plain HTTP.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Enable TLS on Jellyfin or place behind a reverse proxy with TLS.",
                    "asset_ip": "192.168.1.10",
                },
                {
                    "id": "F-MN-003",
                    "title": "RDP enabled on workstation",
                    "description": "Remote Desktop Protocol exposed on desktop-main.",
                    "severity": "high",
                    "category": "exposure",
                    "source_tool": "vuln_scanner",
                    "source_check": "rdp_enabled",
                    "evidence": "TCP connection to 192.168.1.100:3389 completes and returns RDP handshake.",
                    "cve_ids": [],
                    "cwe_id": "CWE-284",
                    "remediation": "Disable RDP if not needed; otherwise restrict via firewall rules and enable NLA.",
                    "asset_ip": "192.168.1.100",
                },
                {
                    "id": "F-MN-004",
                    "title": "IoT camera HTTP without TLS",
                    "description": "Front camera web interface has no TLS support.",
                    "severity": "medium",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_tls",
                    "evidence": "Port 80 on 192.168.1.50 returns HTTP only; no TLS available.",
                    "cve_ids": [],
                    "cwe_id": "CWE-319",
                    "remediation": "Isolate camera on a dedicated IoT VLAN.",
                    "asset_ip": "192.168.1.50",
                },
                {
                    "id": "F-MN-005",
                    "title": "Smart plug HTTP management interface",
                    "description": "Smart plug admin on port 80 over plain HTTP with no auth required.",
                    "severity": "medium",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "http_no_auth",
                    "evidence": "GET http://192.168.1.52/ returns device control page without authentication.",
                    "cve_ids": [],
                    "cwe_id": "CWE-306",
                    "remediation": "Isolate smart plugs on IoT VLAN; use vendor cloud app for management.",
                    "asset_ip": "192.168.1.52",
                },
                {
                    "id": "F-MN-006",
                    "title": "Thermostat self-signed certificate",
                    "description": "Smart thermostat HTTPS uses an untrusted self-signed certificate.",
                    "severity": "low",
                    "category": "misconfig",
                    "source_tool": "vuln_scanner",
                    "source_check": "tls_cert_trust",
                    "evidence": "TLS certificate on 192.168.1.51:443 issued by CN=localhost; not in trust store.",
                    "cve_ids": [],
                    "cwe_id": "CWE-295",
                    "remediation": "Accept risk for IoT VLAN; isolate device from sensitive network segments.",
                    "asset_ip": "192.168.1.51",
                },
            ],
            "threats": [
                {
                    "title": "RDP brute-force attack on workstation",
                    "threat_type": "credential_access",
                    "confidence": 0.75,
                    "description": "Attacker brute-forces RDP credentials on the desktop workstation.",
                },
                {
                    "title": "IoT botnet recruitment",
                    "threat_type": "collection",
                    "confidence": 0.6,
                    "description": "Compromised IoT devices recruited into a botnet via weak web interfaces.",
                },
            ],
        },
        "expected_output": {
            "min_high_critical_count": 1,
            "risk_levels_present": ["low", "medium", "high"],
            "expected_risk_range": {"min": "low", "max": "high"},
            "finding_count": 6,
            "asset_count": 7,
            "zones_affected": ["lan", "iot"],
            "risk_distribution": {
                "low": {"min": 1, "max": 2},
                "medium": {"min": 3, "max": 4},
                "high": {"min": 1, "max": 2},
            },
        },
        "tags": ["mixed_network", "multi_device", "zone_segmentation", "regression"],
    },

    # ------------------------------------------------------------------
    # Scenario 5: drift_detection
    # ------------------------------------------------------------------
    {
        "id": "drift_detection",
        "name": "Two snapshots for configuration drift testing",
        "description": (
            "Provides baseline and current network snapshots to test drift "
            "detection: 2 new assets appearing, 1 new open port on an "
            "existing asset, and 1 zone reclassification.  Verifies the "
            "pipeline detects all four drift events."
        ),
        "input": {
            "baseline": {
                "timestamp": "2025-12-01T00:00:00Z",
                "assets": [
                    {
                        "ip_address": "192.168.1.1",
                        "hostname": "home-router",
                        "asset_type": "router",
                        "zone": "lan",
                        "open_ports": [22, 80, 443],
                    },
                    {
                        "ip_address": "192.168.1.10",
                        "hostname": "nas-primary",
                        "asset_type": "nas",
                        "zone": "lan",
                        "open_ports": [22, 443, 5001],
                    },
                    {
                        "ip_address": "192.168.1.50",
                        "hostname": "cam-backyard",
                        "asset_type": "camera",
                        "zone": "iot",
                        "open_ports": [80, 554],
                    },
                    {
                        "ip_address": "192.168.1.100",
                        "hostname": "desktop-main",
                        "asset_type": "workstation",
                        "zone": "lan",
                        "open_ports": [22],
                    },
                    {
                        "ip_address": "192.168.1.101",
                        "hostname": "laptop-work",
                        "asset_type": "workstation",
                        "zone": "lan",
                        "open_ports": [22],
                    },
                ],
            },
            "current": {
                "timestamp": "2026-01-15T00:00:00Z",
                "assets": [
                    {
                        "ip_address": "192.168.1.1",
                        "hostname": "home-router",
                        "asset_type": "router",
                        "zone": "lan",
                        "open_ports": [22, 80, 443],
                    },
                    {
                        "ip_address": "192.168.1.10",
                        "hostname": "nas-primary",
                        "asset_type": "nas",
                        "zone": "lan",
                        "open_ports": [22, 443, 5001, 8096],
                    },
                    {
                        "ip_address": "192.168.1.50",
                        "hostname": "cam-backyard",
                        "asset_type": "camera",
                        "zone": "dmz",
                        "open_ports": [80, 554],
                    },
                    {
                        "ip_address": "192.168.1.100",
                        "hostname": "desktop-main",
                        "asset_type": "workstation",
                        "zone": "lan",
                        "open_ports": [22],
                    },
                    {
                        "ip_address": "192.168.1.101",
                        "hostname": "laptop-work",
                        "asset_type": "workstation",
                        "zone": "lan",
                        "open_ports": [22],
                    },
                    {
                        "ip_address": "192.168.1.60",
                        "hostname": "smart-speaker",
                        "asset_type": "smart_speaker",
                        "zone": "iot",
                        "open_ports": [80, 8008, 8443],
                    },
                    {
                        "ip_address": "192.168.1.61",
                        "hostname": "smart-display",
                        "asset_type": "smart_display",
                        "zone": "iot",
                        "open_ports": [80, 8008, 8443, 9000],
                    },
                ],
            },
        },
        "expected_output": {
            "new_assets": [
                {"ip_address": "192.168.1.60", "hostname": "smart-speaker"},
                {"ip_address": "192.168.1.61", "hostname": "smart-display"},
            ],
            "new_asset_count": 2,
            "removed_asset_count": 0,
            "port_changes": [
                {
                    "ip_address": "192.168.1.10",
                    "added_ports": [8096],
                    "removed_ports": [],
                },
            ],
            "zone_changes": [
                {
                    "ip_address": "192.168.1.50",
                    "old_zone": "iot",
                    "new_zone": "dmz",
                },
            ],
            "total_drift_alerts": 4,
        },
        "tags": ["drift", "baseline", "snapshot", "new_assets", "regression"],
    },
]


def get_scenario(scenario_id: str) -> dict | None:
    """Return a single scenario by its ``id``, or ``None`` if not found."""
    for scenario in SCENARIOS:
        if scenario["id"] == scenario_id:
            return scenario
    return None


def list_scenario_ids() -> list[str]:
    """Return a list of all available scenario IDs."""
    return [s["id"] for s in SCENARIOS]
