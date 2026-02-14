"""STRIDE and home network threat catalogs."""

STRIDE_CATALOG = {
    "spoofing": {
        "name": "Spoofing",
        "description": "Impersonating something or someone else",
        "examples": [
            "ARP spoofing on local network",
            "DNS spoofing to redirect traffic",
            "MAC address spoofing to bypass ACLs",
            "Rogue DHCP server",
            "Spoofed firmware update server",
        ],
    },
    "tampering": {
        "name": "Tampering",
        "description": "Modifying data or code without authorization",
        "examples": [
            "Man-in-the-middle on unencrypted traffic",
            "DNS response tampering",
            "Firmware modification",
            "Configuration file tampering on NAS",
            "Router configuration manipulation",
        ],
    },
    "repudiation": {
        "name": "Repudiation",
        "description": "Claiming to have not performed an action",
        "examples": [
            "No logging on router admin actions",
            "Missing audit trail on NAS access",
            "Unsigned firmware updates",
            "No authentication on IoT commands",
        ],
    },
    "information_disclosure": {
        "name": "Information Disclosure",
        "description": "Exposing information to unauthorized parties",
        "examples": [
            "Unencrypted HTTP admin interfaces",
            "SMB shares without authentication",
            "SNMP community strings exposed",
            "UPnP device descriptions leaking info",
            "DNS queries visible to ISP",
            "Cleartext credentials in IoT protocols",
        ],
    },
    "denial_of_service": {
        "name": "Denial of Service",
        "description": "Denying or degrading service to users",
        "examples": [
            "WiFi deauthentication attacks",
            "DHCP exhaustion",
            "ARP table overflow on router",
            "DNS amplification from open resolver",
            "IoT device resource exhaustion",
        ],
    },
    "elevation_of_privilege": {
        "name": "Elevation of Privilege",
        "description": "Gaining capabilities without proper authorization",
        "examples": [
            "Default credentials on router/NAS",
            "Exploiting UPnP to open firewall ports",
            "SSH key reuse across devices",
            "Privilege escalation via IoT firmware vulnerability",
            "Lateral movement from IoT to LAN",
        ],
    },
}

HOME_THREAT_CATALOG = {
    "router": [
        {
            "title": "Default or weak router admin credentials",
            "threat_type": "elevation_of_privilege",
            "description": "Router may use default or easily guessable admin credentials, allowing unauthorized configuration changes.",
            "confidence": 0.7,
        },
        {
            "title": "Router firmware not updated",
            "threat_type": "elevation_of_privilege",
            "description": "Outdated firmware may contain known vulnerabilities that can be exploited for full device control.",
            "confidence": 0.6,
        },
        {
            "title": "UPnP enabled allowing automatic port forwarding",
            "threat_type": "tampering",
            "description": "UPnP can be exploited by malware to open firewall ports, exposing internal services to the internet.",
            "confidence": 0.8,
        },
        {
            "title": "DNS traffic interception via unencrypted DNS",
            "threat_type": "information_disclosure",
            "description": "Standard DNS queries are unencrypted, allowing ISP or attackers to monitor browsing activity.",
            "confidence": 0.9,
        },
        {
            "title": "Remote management interface exposed to WAN",
            "threat_type": "spoofing",
            "description": "Router admin interface accessible from the internet increases attack surface significantly.",
            "confidence": 0.5,
        },
        {
            "title": "Weak WiFi encryption or shared PSK",
            "threat_type": "spoofing",
            "description": "WPA2-PSK with shared password across all devices allows any device to decrypt others' traffic.",
            "confidence": 0.6,
        },
    ],
    "nas": [
        {
            "title": "NAS exposed with default credentials",
            "threat_type": "elevation_of_privilege",
            "description": "Default admin accounts on NAS devices allow unauthorized access to stored data.",
            "confidence": 0.6,
        },
        {
            "title": "Unencrypted SMB/NFS file sharing",
            "threat_type": "information_disclosure",
            "description": "File sharing protocols without encryption expose data to network sniffing.",
            "confidence": 0.7,
        },
        {
            "title": "NAS ransomware via exposed services",
            "threat_type": "denial_of_service",
            "description": "Internet-facing NAS services are common targets for ransomware attacks encrypting personal data.",
            "confidence": 0.6,
        },
        {
            "title": "NAS admin interface on HTTP without TLS",
            "threat_type": "information_disclosure",
            "description": "Admin credentials transmitted in cleartext over the network.",
            "confidence": 0.7,
        },
        {
            "title": "Outdated NAS firmware with known CVEs",
            "threat_type": "elevation_of_privilege",
            "description": "Unpatched NAS firmware may contain critical vulnerabilities allowing remote code execution.",
            "confidence": 0.5,
        },
    ],
    "iot": [
        {
            "title": "IoT device with hardcoded credentials",
            "threat_type": "elevation_of_privilege",
            "description": "Many IoT devices ship with hardcoded or unchangeable credentials.",
            "confidence": 0.8,
        },
        {
            "title": "IoT device phoning home to cloud without user consent",
            "threat_type": "information_disclosure",
            "description": "IoT devices may send telemetry, usage data, or recordings to manufacturer cloud services.",
            "confidence": 0.7,
        },
        {
            "title": "IoT device as lateral movement pivot",
            "threat_type": "elevation_of_privilege",
            "description": "Compromised IoT devices on the same network can be used to attack higher-value targets.",
            "confidence": 0.6,
        },
        {
            "title": "Unencrypted IoT communication protocol",
            "threat_type": "information_disclosure",
            "description": "Many IoT protocols (MQTT without TLS, CoAP, HTTP) transmit data in cleartext.",
            "confidence": 0.7,
        },
        {
            "title": "IoT device lacks security updates",
            "threat_type": "elevation_of_privilege",
            "description": "Manufacturer may not provide security patches, leaving known vulnerabilities unaddressed.",
            "confidence": 0.8,
        },
        {
            "title": "IoT device acting as open relay/proxy",
            "threat_type": "tampering",
            "description": "Compromised IoT devices can be enrolled in botnets for DDoS or spam relay.",
            "confidence": 0.5,
        },
    ],
    "workstation": [
        {
            "title": "Workstation with outdated OS or missing patches",
            "threat_type": "elevation_of_privilege",
            "description": "Unpatched operating systems are vulnerable to known exploits.",
            "confidence": 0.5,
        },
        {
            "title": "Open remote access services (RDP/VNC/SSH)",
            "threat_type": "spoofing",
            "description": "Remote access services can be targeted for brute-force or credential stuffing attacks.",
            "confidence": 0.6,
        },
        {
            "title": "File sharing without authentication",
            "threat_type": "information_disclosure",
            "description": "Open SMB/NFS shares expose files to all devices on the network.",
            "confidence": 0.5,
        },
    ],
    "server": [
        {
            "title": "Server with exposed management interfaces",
            "threat_type": "elevation_of_privilege",
            "description": "Web-based admin panels or SSH accessible from untrusted zones.",
            "confidence": 0.6,
        },
        {
            "title": "Database service exposed on network",
            "threat_type": "information_disclosure",
            "description": "Database ports open to the network risk unauthorized data access.",
            "confidence": 0.5,
        },
        {
            "title": "Server running outdated software with known CVEs",
            "threat_type": "elevation_of_privilege",
            "description": "Outdated server software may contain exploitable vulnerabilities.",
            "confidence": 0.5,
        },
    ],
    "camera": [
        {
            "title": "IP camera with default credentials",
            "threat_type": "elevation_of_privilege",
            "description": "Default camera credentials allow unauthorized viewing of video feeds.",
            "confidence": 0.8,
        },
        {
            "title": "Camera video stream accessible without authentication",
            "threat_type": "information_disclosure",
            "description": "RTSP or HTTP streams may be accessible to anyone on the network.",
            "confidence": 0.7,
        },
        {
            "title": "Camera sending footage to cloud without consent",
            "threat_type": "information_disclosure",
            "description": "Camera may upload recordings to manufacturer servers without explicit consent.",
            "confidence": 0.6,
        },
    ],
}

# Zone-level threat templates
ZONE_THREAT_CATALOG = {
    "iot": [
        {
            "title": "IoT zone lacks network isolation",
            "threat_type": "elevation_of_privilege",
            "description": "Without VLAN isolation, compromised IoT devices can access LAN resources directly.",
            "confidence": 0.8,
        },
        {
            "title": "IoT devices communicate with each other unsupervised",
            "threat_type": "tampering",
            "description": "Inter-device communication in IoT zone may allow worm-like propagation.",
            "confidence": 0.5,
        },
    ],
    "guest": [
        {
            "title": "Guest network not isolated from main LAN",
            "threat_type": "elevation_of_privilege",
            "description": "Without proper isolation, guest devices can access internal network resources.",
            "confidence": 0.7,
        },
        {
            "title": "Guest devices performing network reconnaissance",
            "threat_type": "information_disclosure",
            "description": "Untrusted guest devices may scan and enumerate internal network services.",
            "confidence": 0.5,
        },
    ],
    "dmz": [
        {
            "title": "DMZ service compromise leading to lateral movement",
            "threat_type": "elevation_of_privilege",
            "description": "Compromised DMZ service used as pivot to attack internal network.",
            "confidence": 0.6,
        },
    ],
    "lan": [
        {
            "title": "Flat LAN without segmentation",
            "threat_type": "elevation_of_privilege",
            "description": "All devices in the same broadcast domain allows easy lateral movement.",
            "confidence": 0.5,
        },
        {
            "title": "ARP spoofing on unsegmented LAN",
            "threat_type": "spoofing",
            "description": "Attacker on LAN can perform ARP spoofing to intercept traffic between devices.",
            "confidence": 0.6,
        },
    ],
}

# Trust boundary threat templates
TRUST_BOUNDARY_THREATS = {
    ("external", "dmz"): [
        {
            "title": "Internet-facing service exploitation",
            "threat_type": "elevation_of_privilege",
            "description": "Services exposed to the internet are subject to automated scanning and exploitation.",
            "confidence": 0.7,
        },
        {
            "title": "DDoS attack on exposed services",
            "threat_type": "denial_of_service",
            "description": "Internet-facing services can be targeted by distributed denial of service attacks.",
            "confidence": 0.5,
        },
    ],
    ("dmz", "lan"): [
        {
            "title": "Pivot from DMZ to internal LAN",
            "threat_type": "elevation_of_privilege",
            "description": "Attacker who compromises DMZ service attempts to reach internal LAN resources.",
            "confidence": 0.6,
        },
    ],
    ("lan", "iot"): [
        {
            "title": "LAN device compromising IoT devices",
            "threat_type": "tampering",
            "description": "Compromised LAN workstation can attack poorly secured IoT devices.",
            "confidence": 0.5,
        },
        {
            "title": "IoT device attacking LAN resources",
            "threat_type": "elevation_of_privilege",
            "description": "Compromised IoT device attempts to access sensitive LAN resources.",
            "confidence": 0.6,
        },
    ],
    ("lan", "guest"): [
        {
            "title": "Guest device accessing LAN resources",
            "threat_type": "elevation_of_privilege",
            "description": "Insufficient isolation allows guest devices to reach internal services.",
            "confidence": 0.6,
        },
    ],
}
