from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from siem_backend.services.collectors.macos import MacOSLogCollector, normalized_event_to_dict
from siem_backend.data.db import get_db
from siem_backend.services.event_service import EventService

router = APIRouter()


@router.post("/test")
def collect_test(
    last: str = Query(default="2m"),
    max_entries: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict:
    collector = MacOSLogCollector(last=last, max_entries=max_entries)
    events = collector.collect()
    saved_count = EventService().save_normalized_events(db, events)
    return {
        "collected_count": len(events),
        "saved_count": saved_count,
        "events": [normalized_event_to_dict(e) for e in events],
    }
