from __future__ import annotations

import datetime as dt
from typing import List, Optional

from sqlalchemy.orm import Session

from siem_backend.data.event_repository import EventRepository
from siem_backend.data.models import Event
from siem_backend.services.normalization import NormalizedEvent


class EventService:
    def __init__(self, repo: Optional[EventRepository] = None) -> None:
        self._repo = repo or EventRepository()

    def save_normalized_events(self, db: Session, events: List[NormalizedEvent]) -> int:
        to_save = [self._to_model(e) for e in events]
        return self._repo.add_many(db, to_save)

    def _to_model(self, event: NormalizedEvent) -> Event:
        ts = self._parse_ts(event.ts)
        return Event(
            ts=ts,
            source_os=event.source_os,
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
