from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.api.schemas.events import EventOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Event
from siem_backend.services.event_formatter import format_event_description

router = APIRouter()


@router.get("/", response_model=list[EventOut])
def list_events(
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[EventOut]:
    stmt = select(Event).order_by(Event.ts.desc()).limit(limit).offset(offset)
    if severity is not None:
        stmt = stmt.where(Event.severity == severity)

    rows = db.execute(stmt).scalars().all()
    result: list[EventOut] = []
    for row in rows:
        item = EventOut.model_validate(row)
        # Формируем человеко-читаемое описание события
        item.description = format_event_description(row)
        result.append(item)

    return result
