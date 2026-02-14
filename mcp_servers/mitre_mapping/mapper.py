"""MITRE ATT&CK technique mapper for findings and threats."""

import re
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Tactic display-name -> Navigator kebab-case slug
# ---------------------------------------------------------------------------
TACTIC_SLUG: dict[str, str] = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

# ---------------------------------------------------------------------------
# Rule-based mappings  (source_check | category -> techniques)
# ---------------------------------------------------------------------------

# Each entry: (technique_id, technique_name, tactic, sub_technique_id | None, base_confidence)
_Technique = tuple[str, str, str, str | None, float]

SOURCE_CHECK_RULES: dict[str, list[_Technique]] = {
    # --- Web / HTTP ----------------------------------------------------------
    "http_security": [
        ("T1189", "Drive-by Compromise", "Initial Access", None, 0.7),
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "T1071", 0.65),
    ],
    "http_headers": [
        ("T1189", "Drive-by Compromise", "Initial Access", None, 0.6),
        ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution", "T1059", 0.55),
    ],
    "cors_check": [
        ("T1189", "Drive-by Compromise", "Initial Access", None, 0.6),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.5),
    ],
    "cookie_check": [
        ("T1539", "Steal Web Session Cookie", "Credential Access", None, 0.75),
        ("T1185", "Browser Session Hijacking", "Collection", None, 0.6),
    ],
    "csp_check": [
        ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution", "T1059", 0.65),
        ("T1189", "Drive-by Compromise", "Initial Access", None, 0.55),
    ],

    # --- TLS / Crypto --------------------------------------------------------
    "tls_check": [
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.8),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
        ("T1573", "Encrypted Channel", "Command and Control", None, 0.5),
    ],
    "ssl_check": [
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.8),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
    ],
    "certificate_check": [
        ("T1587.003", "Develop Capabilities: Digital Certificates", "Resource Development", "T1587", 0.6),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.55),
    ],

    # --- SSH -----------------------------------------------------------------
    "ssh_check": [
        ("T1021.004", "Remote Services: SSH", "Lateral Movement", "T1021", 0.8),
        ("T1110", "Brute Force", "Credential Access", None, 0.7),
    ],
    "ssh_auth": [
        ("T1110", "Brute Force", "Credential Access", None, 0.75),
        ("T1078", "Valid Accounts", "Persistence", None, 0.6),
    ],

    # --- DNS -----------------------------------------------------------------
    "dns_check": [
        ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "T1071", 0.75),
        ("T1584.002", "Compromise Infrastructure: DNS Server", "Resource Development", "T1584", 0.6),
    ],
    "dns_zone_transfer": [
        ("T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance", "T1590", 0.85),
        ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "T1071", 0.6),
    ],

    # --- Mail / SMTP ---------------------------------------------------------
    "smtp_check": [
        ("T1071.003", "Application Layer Protocol: Mail Protocols", "Command and Control", "T1071", 0.65),
        ("T1566", "Phishing", "Initial Access", None, 0.6),
    ],

    # --- Auth / Password -----------------------------------------------------
    "password_policy": [
        ("T1110", "Brute Force", "Credential Access", None, 0.8),
        ("T1078", "Valid Accounts", "Persistence", None, 0.65),
    ],
    "auth_check": [
        ("T1110", "Brute Force", "Credential Access", None, 0.75),
        ("T1078", "Valid Accounts", "Persistence", None, 0.7),
    ],
    "default_creds": [
        ("T1078.001", "Valid Accounts: Default Accounts", "Persistence", "T1078", 0.9),
        ("T1110", "Brute Force", "Credential Access", None, 0.6),
    ],

    # --- Network services ----------------------------------------------------
    "smb_check": [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "T1021", 0.8),
        ("T1570", "Lateral Tool Transfer", "Lateral Movement", None, 0.6),
    ],
    "rdp_check": [
        ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "T1021", 0.8),
        ("T1110", "Brute Force", "Credential Access", None, 0.6),
    ],
    "vnc_check": [
        ("T1021.005", "Remote Services: VNC", "Lateral Movement", "T1021", 0.8),
        ("T1110", "Brute Force", "Credential Access", None, 0.55),
    ],
    "ftp_check": [
        ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control", "T1071", 0.7),
        ("T1078", "Valid Accounts", "Persistence", None, 0.55),
    ],
    "telnet_check": [
        ("T1021", "Remote Services", "Lateral Movement", None, 0.75),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
    ],
    "snmp_check": [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
        ("T1018", "Remote System Discovery", "Discovery", None, 0.6),
    ],
    "upnp_check": [
        ("T1090", "Proxy", "Command and Control", None, 0.65),
        ("T1018", "Remote System Discovery", "Discovery", None, 0.5),
    ],
    "ntp_check": [
        ("T1498.001", "Network Denial of Service: Direct Network Flood", "Impact", "T1498", 0.55),
    ],

    # --- Firewall / Network --------------------------------------------------
    "firewall_check": [
        ("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion", "T1562", 0.75),
        ("T1090", "Proxy", "Command and Control", None, 0.5),
    ],
    "port_scan": [
        ("T1046", "Network Service Scanning", "Discovery", None, 0.7),
    ],
}

CATEGORY_RULES: dict[str, list[_Technique]] = {
    "vuln": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.7),
        ("T1203", "Exploitation for Client Execution", "Execution", None, 0.5),
    ],
    "misconfig": [
        ("T1562", "Impair Defenses", "Defense Evasion", None, 0.55),
        ("T1078", "Valid Accounts", "Persistence", None, 0.45),
    ],
    "exposure": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.6),
        ("T1133", "External Remote Services", "Persistence", None, 0.5),
    ],
    "info": [
        ("T1592", "Gather Victim Host Information", "Reconnaissance", None, 0.4),
        ("T1018", "Remote System Discovery", "Discovery", None, 0.35),
    ],
}

# ---------------------------------------------------------------------------
# CWE -> ATT&CK mappings
# ---------------------------------------------------------------------------
CWE_TECHNIQUE_MAP: dict[str, list[_Technique]] = {
    "CWE-79": [
        ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution", "T1059", 0.8),
        ("T1185", "Browser Session Hijacking", "Collection", None, 0.6),
    ],
    "CWE-89": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.85),
    ],
    "CWE-200": [
        ("T1005", "Data from Local System", "Collection", None, 0.6),
        ("T1592", "Gather Victim Host Information", "Reconnaissance", None, 0.5),
    ],
    "CWE-250": [
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", None, 0.7),
    ],
    "CWE-269": [
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", None, 0.7),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", None, 0.6),
    ],
    "CWE-284": [
        ("T1078", "Valid Accounts", "Persistence", None, 0.65),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", None, 0.55),
    ],
    "CWE-307": [
        ("T1110", "Brute Force", "Credential Access", None, 0.85),
    ],
    "CWE-311": [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.6),
    ],
    "CWE-319": [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.85),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.7),
    ],
    "CWE-326": [
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.75),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.6),
    ],
    "CWE-327": [
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.75),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.6),
    ],
    "CWE-502": [
        ("T1059", "Command and Scripting Interpreter", "Execution", None, 0.75),
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.65),
    ],
    "CWE-521": [
        ("T1110", "Brute Force", "Credential Access", None, 0.85),
        ("T1078", "Valid Accounts", "Persistence", None, 0.6),
    ],
    "CWE-611": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.7),
        ("T1005", "Data from Local System", "Collection", None, 0.55),
    ],
    "CWE-732": [
        ("T1222", "File and Directory Permissions Modification", "Defense Evasion", None, 0.7),
    ],
    "CWE-798": [
        ("T1078", "Valid Accounts", "Persistence", None, 0.9),
        ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", "T1552", 0.75),
    ],
    "CWE-918": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.7),
        ("T1090", "Proxy", "Command and Control", None, 0.55),
    ],
}

# ---------------------------------------------------------------------------
# Keyword -> ATT&CK heuristic mappings
# ---------------------------------------------------------------------------
_KeywordEntry = tuple[str, str, str, str | None, float]

KEYWORD_RULES: list[tuple[str, list[_KeywordEntry]]] = [
    (r"\bpassword\b", [
        ("T1110", "Brute Force", "Credential Access", None, 0.6),
        ("T1078", "Valid Accounts", "Persistence", None, 0.5),
    ]),
    (r"\btelnet\b", [
        ("T1021", "Remote Services", "Lateral Movement", None, 0.7),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.65),
    ]),
    (r"\bftp\b", [
        ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control", "T1071", 0.65),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.5),
    ]),
    (r"\bsmb\b", [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "T1021", 0.7),
    ]),
    (r"\brdp\b", [
        ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "T1021", 0.7),
    ]),
    (r"\bvnc\b", [
        ("T1021.005", "Remote Services: VNC", "Lateral Movement", "T1021", 0.7),
    ]),
    (r"\bsnmp\b", [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.6),
        ("T1018", "Remote System Discovery", "Discovery", None, 0.5),
    ]),
    (r"\bupnp\b", [
        ("T1090", "Proxy", "Command and Control", None, 0.6),
    ]),
    (r"\badmin\b", [
        ("T1078", "Valid Accounts", "Persistence", None, 0.55),
        ("T1133", "External Remote Services", "Persistence", None, 0.45),
    ]),
    (r"\bdefault.{0,10}cred", [
        ("T1078.001", "Valid Accounts: Default Accounts", "Persistence", "T1078", 0.8),
    ]),
    (r"\bsql.{0,5}inject", [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.8),
    ]),
    (r"\bxss\b|cross.?site.?script", [
        ("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution", "T1059", 0.75),
    ]),
    (r"\bopen.{0,5}port\b", [
        ("T1046", "Network Service Scanning", "Discovery", None, 0.5),
    ]),
    (r"\bunencrypt|\bcleartext|\bplaintext", [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.55),
    ]),
    (r"\bbackdoor\b", [
        ("T1133", "External Remote Services", "Persistence", None, 0.8),
        ("T1505", "Server Software Component", "Persistence", None, 0.7),
    ]),
    (r"\bprivilege.{0,5}escalat", [
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", None, 0.75),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", None, 0.6),
    ]),
    (r"\bremote.{0,5}code.{0,5}exec|\brce\b", [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.85),
        ("T1203", "Exploitation for Client Execution", "Execution", None, 0.7),
    ]),
    (r"\bdenial.{0,5}of.{0,5}service|\bdos\b", [
        ("T1498", "Network Denial of Service", "Impact", None, 0.7),
        ("T1499", "Endpoint Denial of Service", "Impact", None, 0.6),
    ]),
    (r"\bphish", [
        ("T1566", "Phishing", "Initial Access", None, 0.7),
    ]),
    (r"\bransomware\b", [
        ("T1486", "Data Encrypted for Impact", "Impact", None, 0.85),
    ]),
    (r"\bdata.{0,5}exfil", [
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", None, 0.75),
    ]),
    (r"\bweak.{0,5}cipher|\bobsolete.{0,5}(tls|ssl)", [
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.7),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.55),
    ]),
]

# ---------------------------------------------------------------------------
# Service/port -> ATT&CK mappings
# ---------------------------------------------------------------------------
SERVICE_RULES: dict[str, list[_Technique]] = {
    "ssh": [
        ("T1021.004", "Remote Services: SSH", "Lateral Movement", "T1021", 0.5),
    ],
    "ftp": [
        ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control", "T1071", 0.5),
    ],
    "telnet": [
        ("T1021", "Remote Services", "Lateral Movement", None, 0.55),
        ("T1040", "Network Sniffing", "Credential Access", None, 0.5),
    ],
    "smb": [
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "T1021", 0.5),
    ],
    "rdp": [
        ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "T1021", 0.5),
    ],
    "vnc": [
        ("T1021.005", "Remote Services: VNC", "Lateral Movement", "T1021", 0.5),
    ],
    "http": [
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "T1071", 0.35),
    ],
    "https": [
        ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "T1071", 0.3),
    ],
    "dns": [
        ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "T1071", 0.4),
    ],
    "smtp": [
        ("T1071.003", "Application Layer Protocol: Mail Protocols", "Command and Control", "T1071", 0.4),
    ],
    "snmp": [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.5),
    ],
    "mysql": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.45),
    ],
    "postgres": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.45),
    ],
    "mssql": [
        ("T1190", "Exploit Public-Facing Application", "Initial Access", None, 0.45),
    ],
    "ldap": [
        ("T1018", "Remote System Discovery", "Discovery", None, 0.45),
        ("T1087", "Account Discovery", "Discovery", None, 0.4),
    ],
    "kerberos": [
        ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access", None, 0.5),
    ],
}

PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    8080: "http",
    8443: "https",
}

# ---------------------------------------------------------------------------
# STRIDE -> ATT&CK mappings
# ---------------------------------------------------------------------------
STRIDE_TECHNIQUE_MAP: dict[str, list[_Technique]] = {
    "spoofing": [
        ("T1078", "Valid Accounts", "Persistence", None, 0.7),
        ("T1557", "Adversary-in-the-Middle", "Credential Access", None, 0.65),
        ("T1134", "Access Token Manipulation", "Defense Evasion", None, 0.55),
        ("T1036", "Masquerading", "Defense Evasion", None, 0.5),
    ],
    "tampering": [
        ("T1565", "Data Manipulation", "Impact", None, 0.75),
        ("T1565.001", "Data Manipulation: Stored Data Manipulation", "Impact", "T1565", 0.7),
        ("T1565.002", "Data Manipulation: Transmitted Data Manipulation", "Impact", "T1565", 0.65),
    ],
    "repudiation": [
        ("T1070", "Indicator Removal", "Defense Evasion", None, 0.75),
        ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion", "T1070", 0.6),
        ("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion", "T1070", 0.6),
    ],
    "information_disclosure": [
        ("T1040", "Network Sniffing", "Credential Access", None, 0.7),
        ("T1005", "Data from Local System", "Collection", None, 0.65),
        ("T1039", "Data from Network Shared Drive", "Collection", None, 0.55),
        ("T1530", "Data from Cloud Storage", "Collection", None, 0.5),
    ],
    "denial_of_service": [
        ("T1498", "Network Denial of Service", "Impact", None, 0.8),
        ("T1499", "Endpoint Denial of Service", "Impact", None, 0.75),
        ("T1489", "Service Stop", "Impact", None, 0.55),
    ],
    "elevation_of_privilege": [
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", None, 0.8),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", None, 0.75),
        ("T1134", "Access Token Manipulation", "Defense Evasion", None, 0.6),
        ("T1078", "Valid Accounts", "Persistence", None, 0.55),
    ],
}


def _build_mapping(
    technique_id: str,
    technique_name: str,
    tactic: str,
    sub_technique: str | None,
    confidence: float,
    source: str,
    rationale: str,
) -> dict[str, Any]:
    """Build a standardised mapping dict."""
    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "sub_technique": sub_technique,
        "confidence": round(min(max(confidence, 0.0), 1.0), 3),
        "source": source,
        "rationale": rationale,
    }


class MitreMapper:
    """Maps findings and STRIDE threats to MITRE ATT&CK techniques."""

    # --------------------------------------------------------------------- #
    # Public interface
    # --------------------------------------------------------------------- #

    def map_finding(self, finding: dict) -> list[dict]:
        """Map a single finding to ATT&CK techniques.

        Uses a layered strategy:
        1. Exact rule matching (source_check)
        2. Category-based rules
        3. CWE-based mapping
        4. Title/description keyword heuristic matching
        5. Service/port-based mapping
        """
        mappings: list[dict] = []
        source_check = (finding.get("source_check") or "").lower().strip()
        category = (finding.get("category") or "").lower().strip()
        cwe_id = (finding.get("cwe_id") or "").strip().upper()
        title = finding.get("title", "")
        description = finding.get("description", "")
        services = finding.get("services") or []
        open_ports = finding.get("open_ports") or []
        severity = (finding.get("severity") or "").lower().strip()

        severity_boost = self._severity_boost(severity)
        text_blob = f"{title} {description}".lower()

        # 1. Exact source_check rule matching
        if source_check and source_check in SOURCE_CHECK_RULES:
            for tech_id, tech_name, tactic, sub, conf in SOURCE_CHECK_RULES[source_check]:
                mappings.append(_build_mapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    sub_technique=sub,
                    confidence=min(conf + severity_boost, 1.0),
                    source="rule",
                    rationale=f"Matched source_check '{source_check}' rule",
                ))
            logger.debug("Rule match on source_check", source_check=source_check, count=len(mappings))

        # 2. Category-based rules
        if category and category in CATEGORY_RULES:
            for tech_id, tech_name, tactic, sub, conf in CATEGORY_RULES[category]:
                # Skip if already mapped via source_check with higher confidence
                if not self._already_mapped_higher(mappings, tech_id, conf + severity_boost):
                    mappings.append(_build_mapping(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic=tactic,
                        sub_technique=sub,
                        confidence=min(conf + severity_boost, 1.0),
                        source="rule",
                        rationale=f"Matched category '{category}' rule",
                    ))

        # 3. CWE-based mapping
        if cwe_id and cwe_id in CWE_TECHNIQUE_MAP:
            for tech_id, tech_name, tactic, sub, conf in CWE_TECHNIQUE_MAP[cwe_id]:
                if not self._already_mapped_higher(mappings, tech_id, conf + severity_boost):
                    mappings.append(_build_mapping(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactic=tactic,
                        sub_technique=sub,
                        confidence=min(conf + severity_boost, 1.0),
                        source="cwe_mapping",
                        rationale=f"Mapped from {cwe_id}",
                    ))
            logger.debug("CWE mapping", cwe_id=cwe_id)

        # 4. Keyword heuristic matching against title + description
        for pattern, techniques in KEYWORD_RULES:
            if re.search(pattern, text_blob, re.IGNORECASE):
                for tech_id, tech_name, tactic, sub, conf in techniques:
                    if not self._already_mapped_higher(mappings, tech_id, conf):
                        mappings.append(_build_mapping(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            tactic=tactic,
                            sub_technique=sub,
                            confidence=conf,
                            source="heuristic",
                            rationale=f"Keyword match on pattern '{pattern}' in title/description",
                        ))

        # 5. Service/port-based mapping
        resolved_services = set(s.lower().strip() for s in services if isinstance(s, str))
        for port in open_ports:
            svc = PORT_SERVICE_MAP.get(int(port))
            if svc:
                resolved_services.add(svc)

        for svc_name in resolved_services:
            if svc_name in SERVICE_RULES:
                for tech_id, tech_name, tactic, sub, conf in SERVICE_RULES[svc_name]:
                    if not self._already_mapped_higher(mappings, tech_id, conf):
                        mappings.append(_build_mapping(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            tactic=tactic,
                            sub_technique=sub,
                            confidence=conf,
                            source="heuristic",
                            rationale=f"Service '{svc_name}' detected",
                        ))

        if not mappings:
            logger.info("No ATT&CK mapping found for finding", title=title, source_check=source_check)

        return mappings

    def map_threat(self, threat: dict) -> list[dict]:
        """Map a STRIDE threat to ATT&CK techniques.

        Args:
            threat: dict with keys threat_type (STRIDE category), description,
                    and optionally services (list[str]).
        """
        threat_type = (threat.get("threat_type") or "").lower().strip()
        description = threat.get("description", "")
        services = threat.get("services") or []

        mappings: list[dict] = []

        # STRIDE -> ATT&CK mapping
        if threat_type in STRIDE_TECHNIQUE_MAP:
            for tech_id, tech_name, tactic, sub, conf in STRIDE_TECHNIQUE_MAP[threat_type]:
                mappings.append(_build_mapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    sub_technique=sub,
                    confidence=conf,
                    source="rule",
                    rationale=f"STRIDE '{threat_type}' mapping",
                ))
        else:
            logger.warning("Unknown STRIDE threat type", threat_type=threat_type)

        # Keyword heuristic on description
        text_blob = description.lower()
        for pattern, techniques in KEYWORD_RULES:
            if re.search(pattern, text_blob, re.IGNORECASE):
                for tech_id, tech_name, tactic, sub, conf in techniques:
                    if not self._already_mapped_higher(mappings, tech_id, conf):
                        mappings.append(_build_mapping(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            tactic=tactic,
                            sub_technique=sub,
                            confidence=conf,
                            source="heuristic",
                            rationale=f"Keyword match on pattern '{pattern}' in threat description",
                        ))

        # Service-based augmentation
        for svc_name in services:
            svc_name = svc_name.lower().strip()
            if svc_name in SERVICE_RULES:
                for tech_id, tech_name, tactic, sub, conf in SERVICE_RULES[svc_name]:
                    if not self._already_mapped_higher(mappings, tech_id, conf):
                        mappings.append(_build_mapping(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            tactic=tactic,
                            sub_technique=sub,
                            confidence=conf,
                            source="heuristic",
                            rationale=f"Service '{svc_name}' associated with threat",
                        ))

        return mappings

    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _severity_boost(severity: str) -> float:
        """Return a small confidence boost based on finding severity."""
        return {
            "critical": 0.15,
            "high": 0.10,
            "medium": 0.05,
            "low": 0.0,
            "info": -0.05,
        }.get(severity, 0.0)

    @staticmethod
    def _already_mapped_higher(
        mappings: list[dict], technique_id: str, new_confidence: float,
    ) -> bool:
        """Return True if *technique_id* already exists in *mappings* with
        equal or higher confidence."""
        for m in mappings:
            if m["technique_id"] == technique_id and m["confidence"] >= new_confidence:
                return True
        return False
