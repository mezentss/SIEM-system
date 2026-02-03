from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.api.schemas.notifications import NotificationOut
from siem_backend.data.db import get_db
from siem_backend.data.models import Notification
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
    stmt = select(Notification).order_by(Notification.created_at.desc()).limit(limit).offset(offset)

    if severity is not None:
        stmt = stmt.where(Notification.severity == severity)

    if notification_type is not None:
        stmt = stmt.where(Notification.notification_type == notification_type)

    if channel is not None:
        stmt = stmt.where(Notification.channel == channel)

    if status is not None:
        stmt = stmt.where(Notification.status == status)

    rows = db.execute(stmt).scalars().all()
    return [NotificationOut.model_validate(r) for r in rows]


@router.get("/{notification_id}", response_model=NotificationOut)
def get_notification(
    notification_id: int,
    db: Session = Depends(get_db),
) -> NotificationOut:
    from fastapi import HTTPException

    stmt = select(Notification).where(Notification.id == notification_id)
    notification = db.execute(stmt).scalar_one_or_none()

    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")

    return NotificationOut.model_validate(notification)


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
    return NotificationOut.model_validate(notification)