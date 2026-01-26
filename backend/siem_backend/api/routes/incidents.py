from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.api.schemas.incidents import IncidentOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Incident

router = APIRouter()


@router.get("/", response_model=list[IncidentOut])
def list_incidents(
    severity: Optional[Literal["low", "medium", "high", "critical", "warning"]] = Query(default=None),
    incident_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[IncidentOut]:
    """Получить список инцидентов с фильтрацией."""
    stmt = select(Incident).order_by(Incident.detected_at.desc()).limit(limit).offset(offset)

    if severity is not None:
        stmt = stmt.where(Incident.severity == severity)

    if incident_type is not None:
        stmt = stmt.where(Incident.incident_type == incident_type)

    rows = db.execute(stmt).scalars().all()
    return [IncidentOut.model_validate(r) for r in rows]


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
) -> IncidentOut:
    """Получить детали конкретного инцидента."""
    stmt = select(Incident).where(Incident.id == incident_id)
    incident = db.execute(stmt).scalar_one_or_none()

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return IncidentOut.model_validate(incident)
