"""ISO 27005 Risk Matrix implementation with configurable likelihood x impact grid."""
import structlog

logger = structlog.get_logger()

# Valid enum values for type safety
LIKELIHOOD_LEVELS = ("very_low", "low", "medium", "high", "very_high")
IMPACT_LEVELS = ("negligible", "low", "medium", "high", "critical")
RISK_LEVELS = ("low", "medium", "high", "critical")

# Numeric ordering for sorting / comparison
RISK_LEVEL_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

DEFAULT_MATRIX: dict[str, dict[str, str]] = {
    "very_low": {
        "negligible": "low",
        "low": "low",
        "medium": "low",
        "high": "medium",
        "critical": "medium",
    },
    "low": {
        "negligible": "low",
        "low": "low",
        "medium": "medium",
        "high": "medium",
        "critical": "high",
    },
    "medium": {
        "negligible": "low",
        "low": "medium",
        "medium": "medium",
        "high": "high",
        "critical": "high",
    },
    "high": {
        "negligible": "medium",
        "low": "medium",
        "medium": "high",
        "high": "high",
        "critical": "critical",
    },
    "very_high": {
        "negligible": "medium",
        "low": "high",
        "medium": "high",
        "high": "critical",
        "critical": "critical",
    },
}

# Treatment thresholds per risk level
DEFAULT_TREATMENT_THRESHOLDS: dict[str, dict] = {
    "critical": {
        "acceptable": False,
        "allowed_treatments": ["mitigate", "avoid"],
        "requires_escalation": True,
        "max_treatment_timeline_days": 7,
    },
    "high": {
        "acceptable": False,
        "allowed_treatments": ["mitigate", "transfer", "avoid"],
        "requires_escalation": False,
        "max_treatment_timeline_days": 30,
    },
    "medium": {
        "acceptable": True,
        "allowed_treatments": ["mitigate", "transfer", "accept"],
        "requires_escalation": False,
        "max_treatment_timeline_days": 90,
    },
    "low": {
        "acceptable": True,
        "allowed_treatments": ["accept", "mitigate"],
        "requires_escalation": False,
        "max_treatment_timeline_days": None,
    },
}


class RiskMatrix:
    """ISO 27005 compliant risk matrix with configurable dimensions.

    The default matrix is a standard 5x5 grid mapping
    likelihood (very_low..very_high) x impact (negligible..critical) to
    a risk level (low/medium/high/critical).
    """

    def __init__(self, config: dict | None = None) -> None:
        if config and "matrix" in config:
            self._matrix: dict[str, dict[str, str]] = config["matrix"]
            logger.info("Risk matrix loaded from config")
        else:
            self._matrix = DEFAULT_MATRIX
            logger.info("Risk matrix using defaults")

        if config and "thresholds" in config:
            self._thresholds = config["thresholds"]
        else:
            self._thresholds = DEFAULT_TREATMENT_THRESHOLDS

    # ------------------------------------------------------------------
    # Core lookup
    # ------------------------------------------------------------------

    def lookup(self, likelihood: str, impact: str) -> str:
        """Look up the risk level for a given likelihood and impact.

        Args:
            likelihood: One of very_low, low, medium, high, very_high.
            impact: One of negligible, low, medium, high, critical.

        Returns:
            Risk level string (low, medium, high, critical).

        Raises:
            ValueError: If likelihood or impact is not a valid enum value.
        """
        likelihood = likelihood.lower().strip()
        impact = impact.lower().strip()

        if likelihood not in LIKELIHOOD_LEVELS:
            raise ValueError(
                f"Invalid likelihood '{likelihood}'. Must be one of {LIKELIHOOD_LEVELS}"
            )
        if impact not in IMPACT_LEVELS:
            raise ValueError(
                f"Invalid impact '{impact}'. Must be one of {IMPACT_LEVELS}"
            )

        risk_level = self._matrix[likelihood][impact]
        logger.debug(
            "Matrix lookup",
            likelihood=likelihood,
            impact=impact,
            risk_level=risk_level,
        )
        return risk_level

    # ------------------------------------------------------------------
    # Treatment thresholds
    # ------------------------------------------------------------------

    def get_treatment_threshold(self, risk_level: str) -> dict:
        """Return acceptable treatments and constraints for a risk level.

        Args:
            risk_level: One of low, medium, high, critical.

        Returns:
            Dict with keys: acceptable, allowed_treatments,
            requires_escalation, max_treatment_timeline_days.
        """
        risk_level = risk_level.lower().strip()
        if risk_level not in RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. Must be one of {RISK_LEVELS}"
            )
        return self._thresholds.get(risk_level, DEFAULT_TREATMENT_THRESHOLDS[risk_level])

    # ------------------------------------------------------------------
    # Visualization helper
    # ------------------------------------------------------------------

    def get_matrix_visualization(self) -> dict:
        """Return the full matrix as a structured dict for frontend display.

        Returns:
            Dict with keys:
                likelihood_levels: ordered list of likelihood values (rows)
                impact_levels: ordered list of impact values (columns)
                risk_levels: ordered list of possible risk outputs
                cells: list of {likelihood, impact, risk_level} for every cell
                matrix: the raw nested dict
        """
        cells: list[dict[str, str]] = []
        for likelihood in LIKELIHOOD_LEVELS:
            for impact in IMPACT_LEVELS:
                cells.append({
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_level": self._matrix[likelihood][impact],
                })

        return {
            "likelihood_levels": list(LIKELIHOOD_LEVELS),
            "impact_levels": list(IMPACT_LEVELS),
            "risk_levels": list(RISK_LEVELS),
            "cells": cells,
            "matrix": self._matrix,
        }
