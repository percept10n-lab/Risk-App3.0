"""ISO 27005 Risk Treatment Advisor.

Recommends treatment strategies (mitigate / transfer / avoid / accept) and
generates specific mitigation actions based on the risk context (finding type,
threat type, asset properties).
"""
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Specific mitigation actions keyed by finding category / keyword
# ---------------------------------------------------------------------------
MITIGATION_CATALOG: list[dict[str, str]] = [
    {
        "match_keywords": ["ssh", "password auth"],
        "action": "Disable password authentication on SSH and enforce key-based authentication only",
        "effort": "low",
    },
    {
        "match_keywords": ["tls", "ssl", "missing tls", "http without tls", "cleartext"],
        "action": "Enable TLS 1.2+ with strong cipher suites and disable legacy SSL/TLS versions",
        "effort": "low",
    },
    {
        "match_keywords": ["recursive dns", "open resolver", "dns amplification"],
        "action": "Restrict DNS recursion to trusted internal networks only",
        "effort": "low",
    },
    {
        "match_keywords": ["default credential", "default password", "factory credential"],
        "action": "Change default credentials immediately and enforce strong password policy",
        "effort": "low",
    },
    {
        "match_keywords": ["upnp"],
        "action": "Disable UPnP on the router and audit any existing port forwarding rules",
        "effort": "low",
    },
    {
        "match_keywords": ["security header", "missing header", "hsts", "x-frame", "csp"],
        "action": "Configure web server security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options)",
        "effort": "low",
    },
    {
        "match_keywords": ["expired certificate", "certificate expir"],
        "action": "Renew TLS certificate and implement automated certificate renewal monitoring",
        "effort": "low",
    },
    {
        "match_keywords": ["telnet"],
        "action": "Disable Telnet service and replace with SSH for remote administration",
        "effort": "low",
    },
    {
        "match_keywords": ["ftp", "cleartext file"],
        "action": "Replace FTP with SFTP or FTPS for encrypted file transfers",
        "effort": "low",
    },
    {
        "match_keywords": ["snmp", "community string"],
        "action": "Upgrade to SNMPv3 with authentication and encryption, or disable SNMP if not needed",
        "effort": "medium",
    },
    {
        "match_keywords": ["firmware", "outdated firmware", "firmware update"],
        "action": "Update device firmware to the latest version and enable automatic update checks",
        "effort": "medium",
    },
    {
        "match_keywords": ["smb", "file sharing", "nfs"],
        "action": "Require authentication on all file shares and enforce SMB signing or use NFSv4 with Kerberos",
        "effort": "medium",
    },
    {
        "match_keywords": ["rdp", "remote desktop"],
        "action": "Restrict RDP access via firewall rules, enforce NLA, and require MFA where possible",
        "effort": "medium",
    },
    {
        "match_keywords": ["vnc"],
        "action": "Restrict VNC access to trusted IPs, enforce strong authentication, and use encrypted tunneling",
        "effort": "medium",
    },
    {
        "match_keywords": ["mqtt", "iot protocol", "coap"],
        "action": "Enable TLS on MQTT broker and require client certificate authentication for IoT devices",
        "effort": "medium",
    },
    {
        "match_keywords": ["vlan", "segmentation", "isolation", "flat network", "lateral movement"],
        "action": "Implement VLAN segmentation to isolate network zones and restrict inter-zone traffic with firewall rules",
        "effort": "high",
    },
    {
        "match_keywords": ["wan accessible", "internet-facing", "internet accessible", "wan exposure"],
        "action": "Remove service from direct internet exposure or place behind VPN/reverse proxy with authentication",
        "effort": "medium",
    },
    {
        "match_keywords": ["open port", "unnecessary service", "attack surface"],
        "action": "Disable unnecessary services and close unused ports to reduce attack surface",
        "effort": "low",
    },
    {
        "match_keywords": ["arp spoof", "arp poison"],
        "action": "Enable Dynamic ARP Inspection (DAI) on managed switches or use static ARP entries for critical hosts",
        "effort": "medium",
    },
    {
        "match_keywords": ["dns spoof", "dns poison"],
        "action": "Enable DNSSEC validation and use DNS-over-HTTPS or DNS-over-TLS for upstream queries",
        "effort": "medium",
    },
    {
        "match_keywords": ["camera", "video stream", "rtsp"],
        "action": "Restrict camera access to authenticated users, disable anonymous RTSP, and isolate cameras on a dedicated VLAN",
        "effort": "medium",
    },
    {
        "match_keywords": ["database", "db exposed", "mysql", "postgres", "redis", "mongodb"],
        "action": "Bind database to localhost or internal interface only, require authentication, and encrypt connections",
        "effort": "medium",
    },
    {
        "match_keywords": ["weak wifi", "wpa2", "psk", "wifi encryption"],
        "action": "Upgrade to WPA3 where supported, use unique per-device credentials (802.1X), or rotate PSK regularly",
        "effort": "medium",
    },
    {
        "match_keywords": ["hardcoded credential", "unchangeable password"],
        "action": "Replace device with one supporting configurable credentials, or isolate device on restricted network segment",
        "effort": "high",
    },
    {
        "match_keywords": ["ransomware", "backup", "data loss"],
        "action": "Implement offline/offsite backups with versioning and test restore procedures regularly",
        "effort": "medium",
    },
]


def _text_blob(asset: dict, finding: dict | None, threat: dict | None) -> str:
    """Combine all relevant text fields into a single lowercase string for keyword matching."""
    parts: list[str] = []

    # Asset fields
    for key in ("asset_type", "hostname", "zone", "os_guess"):
        val = asset.get(key)
        if val:
            parts.append(str(val))
    for svc in asset.get("services", []):
        parts.append(str(svc) if isinstance(svc, str) else str(svc.get("name", "")))

    # Finding fields
    if finding:
        for key in ("title", "description", "category", "remediation", "source_check"):
            val = finding.get(key)
            if val:
                parts.append(str(val))

    # Threat fields
    if threat:
        for key in ("title", "description", "threat_type"):
            val = threat.get(key)
            if val:
                parts.append(str(val))

    return " ".join(parts).lower()


class TreatmentAdvisor:
    """Recommends risk treatment strategies per ISO 27005 clause 9.

    Treatment options:
        mitigate  - Reduce risk by implementing controls
        transfer  - Transfer risk to a third party (insurance, outsourcing)
        avoid     - Eliminate the risk by removing the asset/activity
        accept    - Acknowledge the risk without further action
    """

    def suggest(
        self,
        risk_level: str,
        asset: dict,
        finding: dict | None = None,
        threat: dict | None = None,
    ) -> dict:
        """Suggest treatment strategy and specific mitigation actions.

        Args:
            risk_level: The assessed risk level (low/medium/high/critical).
            asset: Asset dict with ip_address, asset_type, zone, etc.
            finding: Optional finding dict with title, description, severity, etc.
            threat: Optional threat dict with title, threat_type, description, etc.

        Returns:
            Dict with recommended_treatment, treatment_options,
            mitigation_actions, and rationale.
        """
        risk_level = risk_level.lower().strip()
        asset_type = asset.get("asset_type", "unknown")

        recommended, rationale = self._determine_treatment(risk_level, asset_type, finding, threat)
        treatment_options = self._build_treatment_options(risk_level, asset_type)
        mitigation_actions = self._find_mitigation_actions(asset, finding, threat)

        # If the recommended treatment is mitigate but we found no specific
        # actions, add a generic one so the caller always has something actionable.
        if recommended == "mitigate" and not mitigation_actions:
            mitigation_actions.append({
                "action": "Perform a detailed security assessment and implement controls proportional to the risk level",
                "effort": "medium",
            })

        result = {
            "recommended_treatment": recommended,
            "treatment_options": treatment_options,
            "mitigation_actions": mitigation_actions,
            "rationale": rationale,
        }

        logger.info(
            "Treatment suggestion generated",
            risk_level=risk_level,
            recommended=recommended,
            action_count=len(mitigation_actions),
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _determine_treatment(
        self,
        risk_level: str,
        asset_type: str,
        finding: dict | None,
        threat: dict | None,
    ) -> tuple[str, str]:
        """Choose the primary recommended treatment and provide rationale."""

        if risk_level == "critical":
            return (
                "mitigate",
                "Critical risk requires immediate mitigation. The combination of high likelihood "
                "and severe impact means this risk cannot be accepted or deferred. Implement "
                "controls to reduce risk to an acceptable level as the highest priority.",
            )

        if risk_level == "high":
            # Infrastructure assets may be candidates for transfer
            if asset_type in ("router", "nas", "server"):
                return (
                    "mitigate",
                    "High risk on infrastructure asset requires active mitigation. "
                    "Risk transfer (e.g., managed security service) is also viable "
                    "for infrastructure assets if internal resources are limited. "
                    "Risk should not be accepted at this level.",
                )
            return (
                "mitigate",
                "High risk requires mitigation through implementing additional security "
                "controls. The current exposure level is above the organization's risk "
                "appetite and should be reduced within 30 days.",
            )

        if risk_level == "medium":
            # If there is a straightforward fix, recommend mitigate
            if finding and finding.get("remediation"):
                return (
                    "mitigate",
                    "Medium risk with a known remediation path. Mitigation is recommended "
                    "as a cost-effective approach. Acceptance with documented justification "
                    "is also permissible if mitigation cost exceeds the potential loss.",
                )
            return (
                "accept",
                "Medium risk may be accepted with documented justification if the cost "
                "of mitigation exceeds the expected loss. Consider periodic review to "
                "ensure risk level does not increase over time.",
            )

        # low
        return (
            "accept",
            "Low risk is within the organization's risk appetite. Acceptance is "
            "appropriate. Monitor for changes in threat landscape or asset "
            "criticality that could elevate this risk.",
        )

    def _build_treatment_options(self, risk_level: str, asset_type: str) -> list[dict]:
        """Build a comprehensive list of all applicable treatment options with pros/cons."""
        options: list[dict] = []

        # Mitigate
        mitigate_option: dict = {
            "treatment": "mitigate",
            "description": "Implement security controls to reduce likelihood and/or impact",
            "pros": [
                "Directly reduces risk exposure",
                "Demonstrates due diligence",
                "Improves overall security posture",
            ],
            "cons": [
                "Requires investment of time and resources",
                "May introduce operational complexity",
            ],
        }
        if risk_level in ("critical", "high"):
            mitigate_option["recommendation_strength"] = "strongly_recommended"
        elif risk_level == "medium":
            mitigate_option["recommendation_strength"] = "recommended"
        else:
            mitigate_option["recommendation_strength"] = "optional"
        options.append(mitigate_option)

        # Transfer
        transfer_option: dict = {
            "treatment": "transfer",
            "description": "Transfer risk to a third party through insurance, outsourcing, or managed services",
            "pros": [
                "Reduces financial exposure from incidents",
                "Leverages specialist expertise",
            ],
            "cons": [
                "Does not eliminate the underlying vulnerability",
                "Ongoing cost for insurance/service",
                "Residual risk remains",
            ],
        }
        if risk_level == "high" and asset_type in ("router", "nas", "server"):
            transfer_option["recommendation_strength"] = "viable_alternative"
        elif risk_level in ("critical", "high"):
            transfer_option["recommendation_strength"] = "supplementary"
        else:
            transfer_option["recommendation_strength"] = "optional"
        options.append(transfer_option)

        # Avoid
        avoid_option: dict = {
            "treatment": "avoid",
            "description": "Eliminate the risk entirely by removing the asset, service, or activity",
            "pros": [
                "Complete elimination of risk",
                "No residual risk remains",
            ],
            "cons": [
                "Loss of functionality or service",
                "May not be feasible for essential assets",
            ],
        }
        if risk_level == "critical":
            avoid_option["recommendation_strength"] = "consider_if_mitigation_infeasible"
        else:
            avoid_option["recommendation_strength"] = "situational"
        options.append(avoid_option)

        # Accept
        accept_option: dict = {
            "treatment": "accept",
            "description": "Acknowledge the risk without further action; document the acceptance decision",
            "pros": [
                "No implementation cost",
                "Appropriate for low-impact risks",
            ],
            "cons": [
                "Risk exposure remains unchanged",
                "Requires documented justification",
                "Must be re-evaluated periodically",
            ],
        }
        if risk_level in ("critical", "high"):
            accept_option["recommendation_strength"] = "not_recommended"
        elif risk_level == "medium":
            accept_option["recommendation_strength"] = "acceptable_with_justification"
        else:
            accept_option["recommendation_strength"] = "recommended"
        options.append(accept_option)

        return options

    def _find_mitigation_actions(
        self,
        asset: dict,
        finding: dict | None,
        threat: dict | None,
    ) -> list[dict]:
        """Search the mitigation catalog for actions matching the context."""
        blob = _text_blob(asset, finding, threat)
        actions: list[dict] = []
        seen_actions: set[str] = set()

        for entry in MITIGATION_CATALOG:
            for keyword in entry["match_keywords"]:
                if keyword in blob and entry["action"] not in seen_actions:
                    actions.append({
                        "action": entry["action"],
                        "effort": entry["effort"],
                    })
                    seen_actions.add(entry["action"])
                    break  # one match per catalog entry is sufficient

        # If the finding itself carries a remediation string, include it
        if finding and finding.get("remediation"):
            remediation = finding["remediation"]
            if remediation not in seen_actions:
                actions.append({
                    "action": remediation,
                    "effort": "unknown",
                    "source": "finding_remediation",
                })

        return actions
