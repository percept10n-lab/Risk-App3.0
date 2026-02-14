import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.audit_event import AuditEvent


class AuditTrail:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        event_type: str,
        entity_type: str,
        entity_id: str,
        actor: str,
        action: str,
        run_id: str | None = None,
        old_value: dict | None = None,
        new_value: dict | None = None,
        rationale: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            id=str(uuid.uuid4()),
            run_id=run_id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            action=action,
            old_value=old_value,
            new_value=new_value,
            rationale=rationale,
            timestamp=datetime.utcnow(),
        )
        self.db.add(event)
        await self.db.flush()
        return event

    async def get_trail(
        self,
        run_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        query = select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit)
        if run_id:
            query = query.where(AuditEvent.run_id == run_id)
        if entity_type:
            query = query.where(AuditEvent.entity_type == entity_type)
        if entity_id:
            query = query.where(AuditEvent.entity_id == entity_id)
        result = await self.db.execute(query)
        return list(result.scalars().all())
