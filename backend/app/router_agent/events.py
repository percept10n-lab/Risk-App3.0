import uuid
from datetime import datetime
from typing import Any, Callable, Awaitable
import structlog

logger = structlog.get_logger()


class Event:
    def __init__(self, event_type: str, data: dict, source: str = "system"):
        self.id = str(uuid.uuid4())
        self.event_type = event_type
        self.data = data
        self.source = source
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "data": self.data,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
        }


class EventBus:
    def __init__(self):
        self._handlers: dict[str, list[Callable[[Event], Awaitable[None]]]] = {}
        self._log: list[dict] = []

    def subscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def publish(self, event: Event):
        self._log.append(event.to_dict())
        logger.info("Event published", event_type=event.event_type, event_id=event.id)

        handlers = self._handlers.get(event.event_type, [])
        handlers += self._handlers.get("*", [])

        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("Event handler error", event_type=event.event_type, error=str(e))

    def get_log(self, event_type: str | None = None, limit: int = 100) -> list[dict]:
        events = self._log
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        return events[-limit:]
