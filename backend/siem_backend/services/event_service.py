from __future__ import annotations

import datetime as dt
from typing import List, Optional

from sqlalchemy.orm import Session

from siem_backend.data.event_repository import EventRepository
from siem_backend.data.models import Event
from siem_backend.services.normalization import NormalizedEvent
from siem_backend.services.notifications import NotificationService


class EventService:
    def __init__(
        self,
        repo: Optional[EventRepository] = None,
        notification_service: Optional[NotificationService] = None,
    ) -> None:
        self._repo = repo or EventRepository()
        self._notification_service = notification_service or NotificationService()

    def save_normalized_events(self, db: Session, events: List[NormalizedEvent]) -> int:
        to_save = [self._to_model(e) for e in events]
        if not to_save:
            return 0
        since = min(e.ts for e in to_save)
        until = max(e.ts for e in to_save)
        existing = self._repo.get_existing_signatures(db, since, until)
        unique: List[Event] = []
        for e in to_save:
            key_ts = e.ts.replace(microsecond=0) if hasattr(e.ts, "replace") else e.ts
            key = (key_ts, e.message or "", e.source_os or "")
            if key not in existing:
                unique.append(e)
                existing.add(key)
        if not unique:
            return 0
        saved_count = self._repo.add_many(db, unique)
        for event_model in unique:
            if event_model.severity == "critical":
                try:
                    self._notification_service.notify_critical_event(db, event_model)
                except Exception:
                    pass
        return saved_count

    def _to_model(self, event: NormalizedEvent) -> Event:
        ts = self._parse_ts(event.ts)
        return Event(
            ts=ts,
            source_os=event.source_os,
            source_category=event.source_category,
            event_type=event.event_type,
            severity=event.severity,
            message=event.message,
            raw_data=event.raw_data,
        )

    def _parse_ts(self, ts: str) -> dt.datetime:
        try:
            parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return dt.datetime.utcnow()
        if parsed.tzinfo is None:
            return parsed
        return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)