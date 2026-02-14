"""ATT&CK Navigator v4.x layer exporter."""

from typing import Any

import structlog

from mcp_servers.mitre_mapping.mapper import TACTIC_SLUG

logger = structlog.get_logger()


def _confidence_color(confidence: float) -> str:
    """Map a 0.0-1.0 confidence score to a hex colour string."""
    if confidence > 0.8:
        return "#ff0000"
    if confidence > 0.6:
        return "#ff6666"
    if confidence > 0.4:
        return "#ffaa00"
    return "#ffdd00"


def _tactic_to_slug(tactic_display: str) -> str:
    """Convert a tactic display name to the Navigator kebab-case slug."""
    slug = TACTIC_SLUG.get(tactic_display)
    if slug:
        return slug
    # Fallback: lowercase + replace spaces with hyphens
    return tactic_display.lower().replace(" ", "-").replace("_", "-")


class NavigatorExporter:
    """Exports ATT&CK mappings as Navigator v4.x layer JSON."""

    def export_layer(
        self,
        mappings: list[dict],
        layer_name: str = "Risk Platform Findings",
    ) -> dict[str, Any]:
        """Generate a valid ATT&CK Navigator v4.x layer from mappings.

        When multiple mappings target the same technique+tactic pair the
        highest confidence is kept. Comments and metadata sources are
        aggregated.

        Args:
            mappings: List of mapping dicts as returned by MitreMapper.
            layer_name: Human-readable layer name.

        Returns:
            A dict that can be serialised to JSON and imported into
            ATT&CK Navigator.
        """
        # Aggregate by (technique_id, tactic_slug)
        aggregated: dict[tuple[str, str], dict] = {}

        for m in mappings:
            tech_id = m.get("technique_id", "")
            tactic_display = m.get("tactic", "")
            tactic_slug = _tactic_to_slug(tactic_display)
            confidence = float(m.get("confidence", 0.0))
            source = m.get("source", "unknown")
            rationale = m.get("rationale", "")
            technique_name = m.get("technique_name", "")

            key = (tech_id, tactic_slug)

            if key not in aggregated:
                aggregated[key] = {
                    "technique_id": tech_id,
                    "technique_name": technique_name,
                    "tactic_slug": tactic_slug,
                    "max_confidence": confidence,
                    "comments": [rationale] if rationale else [],
                    "sources": {source} if source else set(),
                }
            else:
                existing = aggregated[key]
                if confidence > existing["max_confidence"]:
                    existing["max_confidence"] = confidence
                if rationale and rationale not in existing["comments"]:
                    existing["comments"].append(rationale)
                if source:
                    existing["sources"].add(source)

        # Build technique entries
        techniques: list[dict[str, Any]] = []
        for (_tech_id, _tactic_slug), agg in aggregated.items():
            max_conf = agg["max_confidence"]
            score = int(round(max_conf * 100))
            color = _confidence_color(max_conf)
            comment = "; ".join(agg["comments"])
            sources_list = sorted(agg["sources"])

            entry: dict[str, Any] = {
                "techniqueID": agg["technique_id"],
                "tactic": agg["tactic_slug"],
                "color": color,
                "comment": f"Mapped from: {comment}" if comment else "",
                "score": score,
                "enabled": True,
                "metadata": [
                    {"name": "source", "value": ", ".join(sources_list)},
                ],
            }
            techniques.append(entry)

        # Sort for deterministic output
        techniques.sort(key=lambda t: (t["techniqueID"], t["tactic"]))

        layer: dict[str, Any] = {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Auto-generated ATT&CK layer from Risk Platform ({len(techniques)} techniques mapped)",
            "filters": {
                "platforms": ["Linux", "Windows", "macOS", "Network"],
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
        }

        logger.info(
            "Navigator layer exported",
            layer_name=layer_name,
            technique_count=len(techniques),
        )
        return layer
