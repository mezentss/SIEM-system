from __future__ import annotations

from typing import Sequence

from sqlalchemy.orm import Session

from siem_backend.data.models import Event


class EventRepository:
    def add_many(self, db: Session, events: Sequence[Event]) -> int:
        if not events:
            return 0

        db.add_all(list(events))
        db.commit()
        return len(events)
