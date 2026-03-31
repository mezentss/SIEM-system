from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from siem_backend.api.schemas.notifications import NotificationOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Notification, NotificationType, SeverityLevel
from siem_backend.services.notifications import NotificationService

router = APIRouter()


@router.get("/", response_model=list[NotificationOut])
def list_notifications(
    severity: Optional[Literal["low", "medium", "high", "critical", "warning"]] = Query(default=None),
    notification_type: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    status: Optional[Literal["pending", "sent", "failed"]] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[NotificationOut]:
    stmt = (
        select(Notification)
        .options(
            joinedload(Notification.notification_type_rel),
            joinedload(Notification.severity_rel),
        )
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    if severity is not None:
        severity_stmt = select(SeverityLevel.id).where(SeverityLevel.name == severity)
        severity_id = db.execute(severity_stmt).scalar_one_or_none()
        if severity_id:
            stmt = stmt.where(Notification.severity_id == severity_id)

    if notification_type is not None:
        type_stmt = select(NotificationType.id).where(NotificationType.name == notification_type)
        type_id = db.execute(type_stmt).scalar_one_or_none()
        if type_id:
            stmt = stmt.where(Notification.notification_type_id == type_id)

    if channel is not None:
        stmt = stmt.where(Notification.channel == channel)

    if status is not None:
        stmt = stmt.where(Notification.status == status)

    rows = db.execute(stmt).scalars().unique().all()
    
    result: list[NotificationOut] = []
    for row in rows:
        notification_type_name = row.notification_type_rel.name if row.notification_type_rel else "unknown"
        severity_name = row.severity_rel.name if row.severity_rel else "unknown"
        
        item = NotificationOut(
            id=row.id,
            created_at=row.created_at,
            notification_type=notification_type_name,
            severity=severity_name,
            title=row.title,
            message=row.message,
            incident_id=row.incident_id,
            event_id=row.event_id,
            channel=row.channel,
            status=row.status,
            details=row.details or {},
        )
        result.append(item)
    
    return result


@router.get("/{notification_id}", response_model=NotificationOut)
def get_notification(
    notification_id: int,
    db: Session = Depends(get_db),
) -> NotificationOut:
    stmt = (
        select(Notification)
        .options(
            joinedload(Notification.notification_type_rel),
            joinedload(Notification.severity_rel),
        )
        .where(Notification.id == notification_id)
    )
    notification = db.execute(stmt).scalar_one_or_none()

    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")

    notification_type_name = notification.notification_type_rel.name if notification.notification_type_rel else "unknown"
    severity_name = notification.severity_rel.name if notification.severity_rel else "unknown"

    return NotificationOut(
        id=notification.id,
        created_at=notification.created_at,
        notification_type=notification_type_name,
        severity=severity_name,
        title=notification.title,
        message=notification.message,
        incident_id=notification.incident_id,
        event_id=notification.event_id,
        channel=notification.channel,
        status=notification.status,
        details=notification.details or {},
    )


@router.post("/test", response_model=NotificationOut)
def send_test_notification(
    db: Session = Depends(get_db),
) -> NotificationOut:
    service = NotificationService()
    notification = service.create_notification(
        db=db,
        notification_type="test",
        severity="critical",
        title="SIEM test notification",
        message="Это тестовое уведомление из SIEM через Telegram.",
    )
    
    notification_type_name = service.get_notification_type_name(db, notification)
    severity_name = service.get_severity_name(db, notification)
    
    return NotificationOut(
        id=notification.id,
        created_at=notification.created_at,
        notification_type=notification_type_name,
        severity=severity_name,
        title=notification.title,
        message=notification.message,
        incident_id=notification.incident_id,
        event_id=notification.event_id,
        channel=notification.channel,
        status=notification.status,
        details=notification.details or {},
    )
