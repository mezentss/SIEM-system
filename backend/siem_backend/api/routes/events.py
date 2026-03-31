from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from siem_backend.api.schemas.events import EventOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Event, EventType, SeverityLevel, SourceCategoryRef, SourceOS
from siem_backend.services.event_formatter import format_event_description

router = APIRouter()


@router.get("/", response_model=list[EventOut])
def list_events(
    severity: Optional[Literal["low", "medium", "high", "critical"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[EventOut]:
    stmt = (
        select(Event)
        .options(
            joinedload(Event.source_os_rel),
            joinedload(Event.source_category_rel),
            joinedload(Event.event_type_rel),
            joinedload(Event.severity_rel),
        )
        .order_by(Event.ts.desc())
        .limit(limit)
        .offset(offset)
    )
    
    if severity is not None:
        # Получаем ID уровня серьёзности
        severity_stmt = select(SeverityLevel.id).where(SeverityLevel.name == severity)
        severity_id = db.execute(severity_stmt).scalar_one_or_none()
        if severity_id:
            stmt = stmt.where(Event.severity_id == severity_id)

    rows = db.execute(stmt).scalars().unique().all()
    result: list[EventOut] = []
    
    for row in rows:
        # Получаем названия из связанных объектов
        source_os_name = row.source_os_rel.name if row.source_os_rel else "unknown"
        source_category_name = row.source_category_rel.name if row.source_category_rel else "unknown"
        event_type_name = row.event_type_rel.name if row.event_type_rel else "unknown"
        severity_name = row.severity_rel.name if row.severity_rel else "unknown"
        
        item = EventOut(
            id=row.id,
            ts=row.ts,
            source_os=source_os_name,
            source_category=source_category_name,
            event_type=event_type_name,
            severity=severity_name,
            message=row.message,
            description=format_event_description(row),
            raw_data=row.raw_data or {},
        )
        result.append(item)

    return result
