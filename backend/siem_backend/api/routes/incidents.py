from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.api.schemas.incidents import AdviceOut, IncidentOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Incident
from siem_backend.services.advice import get_advice_for_severity
from siem_backend.services.event_formatter import format_incident_friendly_description

router = APIRouter()


@router.get("/", response_model=list[IncidentOut])
def list_incidents(
    severity: Optional[Literal["low", "medium", "high", "critical", "warning"]] = Query(default=None),
    incident_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[IncidentOut]:
    stmt = select(Incident).order_by(Incident.detected_at.desc()).limit(limit).offset(offset)

    if severity is not None:
        stmt = stmt.where(Incident.severity == severity)

    if incident_type is not None:
        stmt = stmt.where(Incident.incident_type == incident_type)

    rows = db.execute(stmt).scalars().all()

    result: list[IncidentOut] = []
    for row in rows:
        item = IncidentOut.model_validate(row)
        item.friendly_description = format_incident_friendly_description(row)
        advice = get_advice_for_severity(row.severity)
        item.advice = AdviceOut(**advice)
        result.append(item)

    return result


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
) -> IncidentOut:
    stmt = select(Incident).where(Incident.id == incident_id)
    incident = db.execute(stmt).scalar_one_or_none()

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    item = IncidentOut.model_validate(incident)
    item.friendly_description = format_incident_friendly_description(incident)
    advice = get_advice_for_severity(incident.severity)
    item.advice = AdviceOut(**advice)
    return item
