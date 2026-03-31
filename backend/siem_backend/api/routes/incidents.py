from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from siem_backend.api.auth import get_current_user
from siem_backend.api.schemas.incidents import AdviceOut, IncidentOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Incident, IncidentType, SeverityLevel
from siem_backend.data.models_user import User
from siem_backend.services.advice import get_advice_for_severity
from siem_backend.services.event_formatter import format_incident_friendly_description
from siem_backend.services.incident_service import IncidentService

router = APIRouter()


class ResolveIncidentRequest(BaseModel):
    notes: Optional[str] = None


@router.get("/", response_model=list[IncidentOut])
def list_incidents(
    severity: Optional[Literal["low", "medium", "high", "critical", "warning"]] = Query(default=None),
    incident_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[IncidentOut]:
    stmt = (
        select(Incident)
        .options(
            joinedload(Incident.incident_type_rel),
            joinedload(Incident.severity_rel),
        )
        .order_by(Incident.detected_at.desc())
        .limit(limit)
        .offset(offset)
    )

    if severity is not None:
        severity_stmt = select(SeverityLevel.id).where(SeverityLevel.name == severity)
        severity_id = db.execute(severity_stmt).scalar_one_or_none()
        if severity_id:
            stmt = stmt.where(Incident.severity_id == severity_id)

    if incident_type is not None:
        type_stmt = select(IncidentType.id).where(IncidentType.name == incident_type)
        type_id = db.execute(type_stmt).scalar_one_or_none()
        if type_id:
            stmt = stmt.where(Incident.incident_type_id == type_id)

    rows = db.execute(stmt).scalars().unique().all()

    result: list[IncidentOut] = []
    for row in rows:
        # Получаем названия из связанных объектов
        incident_type_name = row.incident_type_rel.name if row.incident_type_rel else "unknown"
        severity_name = row.severity_rel.name if row.severity_rel else "unknown"
        
        item = IncidentOut(
            id=row.id,
            detected_at=row.detected_at,
            incident_type=incident_type_name,
            severity=severity_name,
            description=row.description,
            friendly_description=format_incident_friendly_description(row),
            event_id=row.event_id,
            details=row.details or {},
            advice=get_advice_for_severity(severity_name),
            status=row.status or "active",
            resolved_at=row.resolved_at,
            resolved_by=row.resolved_by,
            resolution_notes=row.resolution_notes,
        )
        result.append(item)

    return result


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
) -> IncidentOut:
    stmt = (
        select(Incident)
        .options(
            joinedload(Incident.incident_type_rel),
            joinedload(Incident.severity_rel),
        )
        .where(Incident.id == incident_id)
    )
    incident = db.execute(stmt).scalar_one_or_none()

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_type_name = incident.incident_type_rel.name if incident.incident_type_rel else "unknown"
    severity_name = incident.severity_rel.name if incident.severity_rel else "unknown"

    item = IncidentOut(
        id=incident.id,
        detected_at=incident.detected_at,
        incident_type=incident_type_name,
        severity=severity_name,
        description=incident.description,
        friendly_description=format_incident_friendly_description(incident),
        event_id=incident.event_id,
        details=incident.details or {},
        advice=get_advice_for_severity(severity_name),
        status=incident.status or "active",
        resolved_at=incident.resolved_at,
        resolved_by=incident.resolved_by,
        resolution_notes=incident.resolution_notes,
    )
    return item


@router.post("/{incident_id}/resolve", response_model=IncidentOut)
def resolve_incident(
    incident_id: int,
    request: ResolveIncidentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentOut:
    """Ручное закрытие инцидента пользователем."""
    service = IncidentService()
    incident = service.resolve_incident(
        db=db,
        incident_id=incident_id,
        username=current_user.username,
        notes=request.notes
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    severity_name = service.get_incident_severity_name(db, incident)
    
    item = IncidentOut(
        id=incident.id,
        detected_at=incident.detected_at,
        incident_type=service.get_incident_type_name(db, incident),
        severity=severity_name,
        description=incident.description,
        friendly_description=format_incident_friendly_description(incident),
        event_id=incident.event_id,
        details=incident.details or {},
        advice=get_advice_for_severity(severity_name),
        status=incident.status or "active",
        resolved_at=incident.resolved_at,
        resolved_by=incident.resolved_by,
        resolution_notes=incident.resolution_notes,
    )
    return item


@router.post("/{incident_id}/reopen", response_model=IncidentOut)
def reopen_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IncidentOut:
    """Повторное открытие закрытого инцидента."""
    service = IncidentService()
    incident = service.reopen_incident(
        db=db,
        incident_id=incident_id,
        username=current_user.username
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    severity_name = service.get_incident_severity_name(db, incident)
    
    item = IncidentOut(
        id=incident.id,
        detected_at=incident.detected_at,
        incident_type=service.get_incident_type_name(db, incident),
        severity=severity_name,
        description=incident.description,
        friendly_description=format_incident_friendly_description(incident),
        event_id=incident.event_id,
        details=incident.details or {},
        advice=get_advice_for_severity(severity_name),
        status=incident.status or "active",
        resolved_at=incident.resolved_at,
        resolved_by=incident.resolved_by,
        resolution_notes=incident.resolution_notes,
    )
    return item
