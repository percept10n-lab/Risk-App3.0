"""ISO 27005 Risk Analyzer - core risk analysis logic.

Implements the risk assessment process defined in ISO 27005:
    1. Identify risk scenario from asset, threat, and finding context
    2. Assess likelihood based on exposure, exploitability, threat capability, controls
    3. Assess impact based on CIA triad analysis and asset criticality
    4. Determine risk level via risk matrix lookup
    5. Recommend treatment strategy
"""
import structlog

from mcp_servers.risk_engine.matrix import RiskMatrix, RISK_LEVEL_ORDER
from mcp_servers.risk_engine.treatment import TreatmentAdvisor

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Likelihood factor mappings
# ---------------------------------------------------------------------------

# Exposure level: how reachable is the asset from hostile networks?
EXPOSURE_SCORES: dict[str, int] = {
    "wan": 4,        # Directly internet-facing
    "dmz": 3,        # In a DMZ, partially exposed
    "iot": 2,        # IoT zone, typically less trusted
    "guest": 2,      # Guest network zone
    "lan": 1,        # Internal LAN, behind perimeter
    "isolated": 0,   # Air-gapped or highly restricted
}

# Map numeric score ranges to likelihood enum values
LIKELIHOOD_ENUM: list[tuple[float, str]] = [
    (1.0, "very_low"),
    (2.0, "low"),
    (3.0, "medium"),
    (4.0, "high"),
    (5.0, "very_high"),
]

IMPACT_ENUM: list[tuple[float, str]] = [
    (1.0, "negligible"),
    (2.0, "low"),
    (3.0, "medium"),
    (4.0, "high"),
    (5.0, "critical"),
]

# Asset criticality → base impact score
CRITICALITY_SCORES: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

# CIA component levels → numeric value
CIA_LEVEL_SCORES: dict[str, float] = {
    "none": 0.0,
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
}

# Threat types that strongly affect each CIA component
CIA_THREAT_MAP: dict[str, dict[str, str]] = {
    "information_disclosure": {"confidentiality": "high", "integrity": "none", "availability": "none"},
    "spoofing":              {"confidentiality": "medium", "integrity": "medium", "availability": "none"},
    "tampering":             {"confidentiality": "none", "integrity": "high", "availability": "low"},
    "repudiation":           {"confidentiality": "low", "integrity": "medium", "availability": "none"},
    "denial_of_service":     {"confidentiality": "none", "integrity": "none", "availability": "high"},
    "elevation_of_privilege": {"confidentiality": "high", "integrity": "high", "availability": "medium"},
}

# Finding categories that indicate CIA impact
CIA_FINDING_INDICATORS: dict[str, dict[str, str]] = {
    "exposure":  {"confidentiality": "high", "integrity": "low", "availability": "none"},
    "misconfig": {"confidentiality": "medium", "integrity": "medium", "availability": "low"},
    "vuln":      {"confidentiality": "high", "integrity": "high", "availability": "medium"},
    "info":      {"confidentiality": "low", "integrity": "none", "availability": "none"},
}


def _score_to_enum(score: float, enum_table: list[tuple[float, str]]) -> str:
    """Convert a numeric score to the nearest enum value."""
    for threshold, label in enum_table:
        if score <= threshold:
            return label
    return enum_table[-1][1]


def _higher_cia(a: str, b: str) -> str:
    """Return the higher of two CIA level strings."""
    return a if CIA_LEVEL_SCORES.get(a, 0) >= CIA_LEVEL_SCORES.get(b, 0) else b


class RiskAnalyzer:
    """Full ISO 27005 risk analysis combining likelihood, impact, and treatment.

    Every computed value includes a human-readable rationale string to ensure
    transparency and auditability of the risk assessment process.
    """

    def __init__(self, matrix: RiskMatrix | None = None) -> None:
        self._matrix = matrix or RiskMatrix()
        self._treatment = TreatmentAdvisor()

    # ==================================================================
    # Public API
    # ==================================================================

    def analyze(
        self,
        asset: dict,
        threat: dict | None = None,
        finding: dict | None = None,
    ) -> dict:
        """Perform a complete ISO 27005 risk analysis.

        Args:
            asset: Asset dict (ip_address, asset_type, zone, criticality,
                   open_ports, services, exposure, ...).
            threat: Optional threat dict (title, threat_type, confidence, ...).
            finding: Optional finding dict (title, severity, category,
                     exploitability_score, ...).

        Returns:
            Comprehensive risk analysis dict with scenario, likelihood, impact,
            risk_level, CIA breakdown, and treatment recommendation.
        """
        scenario = self._build_scenario(asset, threat, finding)

        likelihood, likelihood_rationale, likelihood_factors = self.calculate_likelihood(
            asset, threat, finding
        )

        (
            impact,
            impact_rationale,
            impact_factors,
            cia,
        ) = self.calculate_impact(asset, threat, finding)

        risk_level = self._matrix.lookup(likelihood, impact)

        treatment = self._treatment.suggest(risk_level, asset, finding, threat)

        result = {
            "scenario": scenario,
            "likelihood": likelihood,
            "likelihood_rationale": likelihood_rationale,
            "likelihood_factors": likelihood_factors,
            "impact": impact,
            "impact_rationale": impact_rationale,
            "impact_factors": impact_factors,
            "risk_level": risk_level,
            "confidentiality_impact": cia["confidentiality"],
            "integrity_impact": cia["integrity"],
            "availability_impact": cia["availability"],
            "recommended_treatment": treatment["recommended_treatment"],
            "treatment_rationale": treatment["rationale"],
            "treatment_options": treatment["treatment_options"],
            "mitigation_actions": treatment["mitigation_actions"],
        }

        logger.info(
            "Risk analysis complete",
            asset_ip=asset.get("ip_address", "unknown"),
            risk_level=risk_level,
            likelihood=likelihood,
            impact=impact,
        )
        return result

    # ==================================================================
    # Likelihood calculation
    # ==================================================================

    def calculate_likelihood(
        self,
        asset: dict,
        threat: dict | None = None,
        finding: dict | None = None,
    ) -> tuple[str, str, dict]:
        """Calculate likelihood from exposure, exploitability, threat capability, and controls.

        Returns:
            Tuple of (likelihood_enum, rationale_string, factors_dict).
        """
        factors: dict[str, dict] = {}
        scores: list[float] = []

        # --- Factor 1: Exposure level ---
        zone = asset.get("zone", "lan").lower()
        exposure = asset.get("exposure", {})
        wan_accessible = exposure.get("wan_accessible", False)

        if wan_accessible:
            exposure_key = "wan"
        else:
            exposure_key = zone

        exposure_score = EXPOSURE_SCORES.get(exposure_key, 1)
        # Normalize to 1-5 scale
        normalized_exposure = min(5.0, max(1.0, exposure_score + 1.0))
        scores.append(normalized_exposure)
        factors["exposure_level"] = {
            "value": exposure_key,
            "score": normalized_exposure,
            "description": (
                f"Asset is in the '{zone}' zone"
                + (", directly accessible from WAN" if wan_accessible else "")
                + f". Exposure score: {normalized_exposure:.1f}/5."
            ),
        }

        # --- Factor 2: Exploitability ---
        exploitability_score_raw = 5.0  # default: medium if unknown
        if finding:
            raw = finding.get("exploitability_score")
            if raw is not None:
                try:
                    raw = float(raw)
                except (ValueError, TypeError):
                    raw = 5.0
                # Map 0-10 scale to 1-5
                if raw <= 3:
                    exploitability_score_raw = 1.5
                elif raw <= 6:
                    exploitability_score_raw = 3.0
                elif raw <= 8:
                    exploitability_score_raw = 4.0
                else:
                    exploitability_score_raw = 5.0

            # Also consider severity as a proxy when no exploitability score
            severity = finding.get("severity", "").lower()
            severity_bump = {"critical": 1.0, "high": 0.5, "medium": 0.0, "low": -0.5, "info": -1.0}
            exploitability_score_raw += severity_bump.get(severity, 0.0)
            exploitability_score_raw = min(5.0, max(1.0, exploitability_score_raw))

        scores.append(exploitability_score_raw)
        factors["exploitability"] = {
            "score": exploitability_score_raw,
            "description": (
                f"Exploitability score: {exploitability_score_raw:.1f}/5"
                + (f" (based on finding exploitability_score and severity)" if finding else " (default: no finding data)")
                + "."
            ),
        }

        # --- Factor 3: Threat capability ---
        threat_score = 3.0  # default: medium if no threat data
        if threat:
            confidence = threat.get("confidence", 0.5)
            try:
                confidence = float(confidence)
            except (ValueError, TypeError):
                confidence = 0.5
            # confidence is 0.0-1.0, scale to 1-5
            threat_score = 1.0 + confidence * 4.0

            threat_type = threat.get("threat_type", "").lower()
            # Automated / mass threats are higher capability
            automated_indicators = ["denial_of_service", "elevation_of_privilege"]
            if threat_type in automated_indicators:
                threat_score = min(5.0, threat_score + 0.5)

        scores.append(threat_score)
        factors["threat_capability"] = {
            "score": threat_score,
            "description": (
                f"Threat capability score: {threat_score:.1f}/5"
                + (f" (confidence: {threat.get('confidence', 'N/A')}, type: {threat.get('threat_type', 'N/A')})" if threat else " (default: no threat data)")
                + "."
            ),
        }

        # --- Factor 4: Existing controls (reduces likelihood) ---
        control_reduction = 0.0
        control_notes: list[str] = []

        # Check for controls in asset exposure or services
        services = asset.get("services", [])
        service_names = set()
        for svc in services:
            if isinstance(svc, str):
                service_names.add(svc.lower())
            elif isinstance(svc, dict):
                service_names.add(svc.get("name", "").lower())

        open_ports = set(asset.get("open_ports", []))

        # TLS/HTTPS present → reduces likelihood
        if 443 in open_ports or "https" in service_names:
            control_reduction += 0.5
            control_notes.append("TLS/HTTPS in use (-0.5)")

        # SSH key auth or auth requirements
        if exposure.get("auth_required"):
            control_reduction += 0.5
            control_notes.append("Authentication required (-0.5)")

        # Firewall / ACL
        if exposure.get("firewall") or exposure.get("firewall_rules"):
            control_reduction += 0.5
            control_notes.append("Firewall/ACL in place (-0.5)")

        # VLAN isolation
        if exposure.get("vlan_isolated") or exposure.get("has_isolation"):
            control_reduction += 0.3
            control_notes.append("VLAN isolation (-0.3)")

        factors["existing_controls"] = {
            "reduction": control_reduction,
            "controls_detected": control_notes if control_notes else ["None detected"],
            "description": (
                f"Existing controls reduce likelihood by {control_reduction:.1f} points."
                + (f" Controls: {', '.join(control_notes)}." if control_notes else " No mitigating controls detected.")
            ),
        }

        # --- Combine factors ---
        raw_average = sum(scores) / len(scores)
        adjusted = max(1.0, min(5.0, raw_average - control_reduction))
        likelihood = _score_to_enum(adjusted, LIKELIHOOD_ENUM)

        rationale_parts = [
            f"Likelihood assessed as '{likelihood}' (score {adjusted:.1f}/5).",
            f"Exposure: {factors['exposure_level']['description']}",
            f"Exploitability: {factors['exploitability']['description']}",
            f"Threat capability: {factors['threat_capability']['description']}",
            f"Controls: {factors['existing_controls']['description']}",
        ]
        rationale = " ".join(rationale_parts)

        return likelihood, rationale, factors

    # ==================================================================
    # Impact calculation
    # ==================================================================

    def calculate_impact(
        self,
        asset: dict,
        threat: dict | None = None,
        finding: dict | None = None,
    ) -> tuple[str, str, dict, dict[str, str]]:
        """Calculate impact from asset criticality, data sensitivity, CIA analysis, and blast radius.

        Returns:
            Tuple of (impact_enum, rationale_string, factors_dict, cia_dict).
        """
        factors: dict[str, dict] = {}
        scores: list[float] = []

        # --- Factor 1: Asset criticality ---
        criticality = asset.get("criticality", "medium").lower()
        crit_score = CRITICALITY_SCORES.get(criticality, 2)
        # Normalize to 1-5
        normalized_crit = min(5.0, max(1.0, float(crit_score) + 0.5))
        scores.append(normalized_crit)
        factors["asset_criticality"] = {
            "value": criticality,
            "score": normalized_crit,
            "description": f"Asset criticality is '{criticality}', base impact score {normalized_crit:.1f}/5.",
        }

        # --- Factor 2: Data sensitivity ---
        data_score = 2.0  # default medium
        data_reasons: list[str] = []
        asset_type = asset.get("asset_type", "unknown").lower()

        # NAS / server / database assets typically hold sensitive data
        if asset_type in ("nas", "server"):
            data_score += 1.0
            data_reasons.append(f"{asset_type} likely stores persistent data")

        # Check exposure hints for data sensitivity
        exposure = asset.get("exposure", {})
        if exposure.get("stores_personal_data") or exposure.get("personal_data"):
            data_score += 1.0
            data_reasons.append("personal data stored")
        if exposure.get("stores_financial_data") or exposure.get("financial_data"):
            data_score += 1.5
            data_reasons.append("financial data stored")

        # Finding-level hints
        if finding:
            finding_lower = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            if any(kw in finding_lower for kw in ("personal", "pii", "gdpr", "privacy")):
                data_score += 0.5
                data_reasons.append("finding indicates personal data exposure")
            if any(kw in finding_lower for kw in ("financial", "payment", "credit card", "banking")):
                data_score += 0.5
                data_reasons.append("finding indicates financial data exposure")

        data_score = min(5.0, max(1.0, data_score))
        scores.append(data_score)
        factors["data_sensitivity"] = {
            "score": data_score,
            "reasons": data_reasons if data_reasons else ["No specific data sensitivity indicators"],
            "description": (
                f"Data sensitivity score: {data_score:.1f}/5."
                + (f" Indicators: {', '.join(data_reasons)}." if data_reasons else "")
            ),
        }

        # --- Factor 3: CIA triad analysis ---
        cia: dict[str, str] = {"confidentiality": "none", "integrity": "none", "availability": "none"}

        # From threat type
        if threat:
            threat_type = threat.get("threat_type", "").lower()
            threat_cia = CIA_THREAT_MAP.get(threat_type, {})
            for dim in ("confidentiality", "integrity", "availability"):
                cia[dim] = _higher_cia(cia[dim], threat_cia.get(dim, "none"))

        # From finding category
        if finding:
            category = finding.get("category", "").lower()
            finding_cia = CIA_FINDING_INDICATORS.get(category, {})
            for dim in ("confidentiality", "integrity", "availability"):
                cia[dim] = _higher_cia(cia[dim], finding_cia.get(dim, "none"))

            # Additional heuristics from finding title/description
            finding_text = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            if any(kw in finding_text for kw in ("disclosure", "leak", "expose", "cleartext", "unencrypt")):
                cia["confidentiality"] = _higher_cia(cia["confidentiality"], "high")
            if any(kw in finding_text for kw in ("tamper", "modif", "inject", "misconfig")):
                cia["integrity"] = _higher_cia(cia["integrity"], "medium")
            if any(kw in finding_text for kw in ("dos", "denial", "exhaust", "crash", "unavailab")):
                cia["availability"] = _higher_cia(cia["availability"], "high")

        # Compute CIA composite score (weighted: C=0.4, I=0.35, A=0.25 as a common weighting)
        cia_score = (
            CIA_LEVEL_SCORES[cia["confidentiality"]] * 0.4
            + CIA_LEVEL_SCORES[cia["integrity"]] * 0.35
            + CIA_LEVEL_SCORES[cia["availability"]] * 0.25
        )
        # Normalize: max possible = 3.0, scale to 1-5
        cia_normalized = 1.0 + (cia_score / 3.0) * 4.0
        cia_normalized = min(5.0, max(1.0, cia_normalized))
        scores.append(cia_normalized)

        factors["cia_analysis"] = {
            "confidentiality": cia["confidentiality"],
            "integrity": cia["integrity"],
            "availability": cia["availability"],
            "composite_score": cia_normalized,
            "description": (
                f"CIA analysis - C:{cia['confidentiality']}, I:{cia['integrity']}, "
                f"A:{cia['availability']}. Composite score: {cia_normalized:.1f}/5."
            ),
        }

        # --- Factor 4: Blast radius ---
        blast_score = 2.0  # default: limited blast radius
        blast_reasons: list[str] = []

        # Routers/gateways affect the entire network
        if asset_type in ("router", "gateway", "firewall"):
            blast_score = 5.0
            blast_reasons.append(f"{asset_type} compromise affects entire network segment")
        elif asset_type in ("server", "nas"):
            blast_score = 3.5
            blast_reasons.append(f"{asset_type} compromise may affect multiple dependent services")
        elif asset_type in ("iot", "camera"):
            blast_score = 1.5
            blast_reasons.append(f"{asset_type} compromise has limited direct blast radius")
        elif asset_type in ("workstation",):
            blast_score = 2.0
            blast_reasons.append("workstation compromise affects single user")

        # If there are many open ports, the blast radius is wider
        open_ports = asset.get("open_ports", [])
        if len(open_ports) > 10:
            blast_score = min(5.0, blast_score + 0.5)
            blast_reasons.append(f"large attack surface ({len(open_ports)} open ports)")

        blast_score = min(5.0, max(1.0, blast_score))
        scores.append(blast_score)
        factors["blast_radius"] = {
            "score": blast_score,
            "reasons": blast_reasons if blast_reasons else ["Standard blast radius for asset type"],
            "description": (
                f"Blast radius score: {blast_score:.1f}/5."
                + (f" {'; '.join(blast_reasons)}." if blast_reasons else "")
            ),
        }

        # --- Combine factors ---
        raw_average = sum(scores) / len(scores)
        impact_final = min(5.0, max(1.0, raw_average))
        impact = _score_to_enum(impact_final, IMPACT_ENUM)

        rationale_parts = [
            f"Impact assessed as '{impact}' (score {impact_final:.1f}/5).",
            f"Criticality: {factors['asset_criticality']['description']}",
            f"Data sensitivity: {factors['data_sensitivity']['description']}",
            f"CIA: {factors['cia_analysis']['description']}",
            f"Blast radius: {factors['blast_radius']['description']}",
        ]
        rationale = " ".join(rationale_parts)

        return impact, rationale, factors, cia

    # ==================================================================
    # Scenario builder
    # ==================================================================

    def _build_scenario(
        self,
        asset: dict,
        threat: dict | None,
        finding: dict | None,
    ) -> str:
        """Build a human-readable risk scenario description."""
        parts: list[str] = []

        asset_desc = asset.get("asset_type", "asset")
        asset_ip = asset.get("ip_address", "unknown IP")
        zone = asset.get("zone", "unknown zone")
        hostname = asset.get("hostname")

        asset_label = f"{asset_desc}"
        if hostname:
            asset_label += f" ({hostname})"
        asset_label += f" at {asset_ip} in the {zone} zone"

        if threat and finding:
            parts.append(
                f"The {asset_label} is exposed to the threat "
                f"'{threat.get('title', 'unspecified threat')}' "
                f"({threat.get('threat_type', 'unknown type')}). "
                f"A vulnerability/finding was identified: "
                f"'{finding.get('title', 'unspecified finding')}' "
                f"(severity: {finding.get('severity', 'unspecified')}). "
                f"If exploited, this could lead to "
                f"{threat.get('description', 'adverse impact on the asset')}."
            )
        elif threat:
            parts.append(
                f"The {asset_label} is exposed to the threat "
                f"'{threat.get('title', 'unspecified threat')}' "
                f"({threat.get('threat_type', 'unknown type')}). "
                f"{threat.get('description', 'This could lead to adverse impact on the asset.')}."
            )
        elif finding:
            parts.append(
                f"A vulnerability/finding was identified on {asset_label}: "
                f"'{finding.get('title', 'unspecified finding')}' "
                f"(severity: {finding.get('severity', 'unspecified')}, "
                f"category: {finding.get('category', 'unspecified')}). "
                f"{finding.get('description', 'This may expose the asset to risk.')}."
            )
        else:
            parts.append(
                f"Risk assessment of {asset_label} based on its network "
                f"exposure and configuration. No specific threat or finding "
                f"was provided for this analysis."
            )

        return " ".join(parts)
