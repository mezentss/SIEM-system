from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.api.schemas.events import EventOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Event

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
    return [EventOut.model_validate(r) for r in rows]
