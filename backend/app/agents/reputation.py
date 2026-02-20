"""
Capability Reputation Tracking — EMA-based scoring using existing audit_events table.
"""

import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.models.audit_event import AuditEvent

import structlog

logger = structlog.get_logger()

# Tier thresholds
TIER_THRESHOLDS = {
    "autonomous": 0.9,
    "spot_check": 0.7,
    "supervised": 0.5,
    "restricted": 0.3,
}

DEFAULT_REPUTATION = 0.7
EMA_ALPHA = 0.1  # smoothing factor: R_new = alpha * score + (1 - alpha) * R_old


class ReputationTracker:
    """Tracks per-capability reputation via EMA, persisted in audit_events."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._cache: dict[str, float] = {}
        self._bootstrapped: set[str] = set()

    async def record_outcome(
        self,
        capability: str,
        score: float,
        verification_detail: dict | None = None,
    ) -> float:
        """Log outcome to audit_events and update EMA cache. Returns new score."""
        old_score = await self.get_reputation(capability)

        # EMA update
        new_score = max(0.0, min(1.0, EMA_ALPHA * score + (1 - EMA_ALPHA) * old_score))
        self._cache[capability] = new_score

        # Persist to audit_events
        event = AuditEvent(
            id=str(uuid.uuid4()),
            event_type="llm_reputation",
            entity_type="copilot_capability",
            entity_id=capability,
            actor="governed_copilot",
            action="reputation_update",
            old_value={"score": old_score, "tier": self._score_to_tier(old_score)},
            new_value={
                "score": new_score,
                "tier": self._score_to_tier(new_score),
                "outcome_score": score,
                "verification": verification_detail,
            },
            rationale=f"EMA update: {old_score:.3f} -> {new_score:.3f} (outcome={score})",
        )
        self.db.add(event)

        return new_score

    async def get_reputation(self, capability: str) -> float:
        """Get current reputation score. Bootstraps from audit history if needed."""
        if capability in self._cache:
            return self._cache[capability]

        if capability not in self._bootstrapped:
            await self._bootstrap(capability)

        return self._cache.get(capability, DEFAULT_REPUTATION)

    async def get_tier(self, capability: str) -> str:
        """Map reputation score to governance tier."""
        score = await self.get_reputation(capability)
        return self._score_to_tier(score)

    async def is_allowed(self, capability: str) -> bool:
        """Returns False if capability is quarantined (score < 0.3)."""
        score = await self.get_reputation(capability)
        return score >= TIER_THRESHOLDS["restricted"]

    async def get_all_stats(self) -> dict[str, dict]:
        """Get all capabilities with scores and tiers. For dashboard."""
        # Bootstrap any capabilities not yet in cache
        result = await self.db.execute(
            select(AuditEvent.entity_id)
            .where(AuditEvent.event_type == "llm_reputation")
            .distinct()
        )
        capabilities = {row[0] for row in result.all()}

        for cap in capabilities:
            if cap not in self._cache:
                await self._bootstrap(cap)

        stats = {}
        for cap, score in self._cache.items():
            tier = self._score_to_tier(score)
            stats[cap] = {
                "score": round(score, 3),
                "tier": tier,
                "allowed": score >= TIER_THRESHOLDS["restricted"],
            }

        return stats

    async def _bootstrap(self, capability: str) -> None:
        """Load most recent reputation from audit_events history."""
        result = await self.db.execute(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "llm_reputation",
                AuditEvent.entity_id == capability,
            )
            .order_by(desc(AuditEvent.timestamp))
            .limit(1)
        )
        event = result.scalar_one_or_none()

        if event and event.new_value and "score" in event.new_value:
            self._cache[capability] = event.new_value["score"]
        else:
            self._cache[capability] = DEFAULT_REPUTATION

        self._bootstrapped.add(capability)

    @staticmethod
    def _score_to_tier(score: float) -> str:
        if score >= TIER_THRESHOLDS["autonomous"]:
            return "autonomous"
        if score >= TIER_THRESHOLDS["spot_check"]:
            return "spot_check"
        if score >= TIER_THRESHOLDS["supervised"]:
            return "supervised"
        if score >= TIER_THRESHOLDS["restricted"]:
            return "restricted"
        return "quarantined"
