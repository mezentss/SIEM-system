from __future__ import annotations

from typing import Sequence, Set, Tuple

import datetime as dt
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event


class EventRepository:
    def get_existing_signatures(
        self, db: Session, since: dt.datetime, until: dt.datetime
    ) -> Set[Tuple[dt.datetime, str, str]]:
        stmt = select(Event.ts, Event.message, Event.source_os).where(
            Event.ts >= since,
            Event.ts <= until,
        )
        rows = db.execute(stmt).all()
        out: Set[Tuple[dt.datetime, str, str]] = set()
        for ts, message, source_os in rows:
            key_ts = ts.replace(microsecond=0) if hasattr(ts, "replace") else ts
            out.add((key_ts, message or "", source_os or ""))
        return out

    def add_many(self, db: Session, events: Sequence[Event]) -> int:
        if not events:
            return 0
        db.add_all(list(events))
        db.commit()
        return len(events)