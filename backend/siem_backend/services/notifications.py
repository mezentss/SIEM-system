from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from siem_backend.data.models import Event, Incident, Notification
from siem_backend.data.notification_repository import NotificationRepository


class NotificationChannel(ABC):
    """Базовый класс для каналов отправки уведомлений."""

    @abstractmethod
    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        """Отправляет уведомление через канал."""
        raise NotImplementedError

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Возвращает имя канала."""
        raise NotImplementedError


class InternalChannel(NotificationChannel):
    """Внутренний канал (только сохранение в БД)."""

    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        """Внутренний канал всегда успешен (уведомление уже в БД)."""
        return True

    @property
    def channel_name(self) -> str:
        return "internal"


class NotificationService:
    """Сервис для управления уведомлениями."""

    def __init__(
        self,
        repo: Optional[NotificationRepository] = None,
        channels: Optional[List[NotificationChannel]] = None,
    ) -> None:
        self._repo = repo or NotificationRepository()
        self._channels = channels or [InternalChannel()]

    def create_notification(
        self,
        db: Session,
        notification_type: str,
        severity: str,
        title: str,
        message: str,
        incident_id: Optional[int] = None,
        event_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Notification:
        """Создает и отправляет уведомление."""
        notification = Notification(
            notification_type=notification_type,
            severity=severity,
            title=title,
            message=message,
            incident_id=incident_id,
            event_id=event_id,
            details=details or {},
            channel="internal",
            status="pending",
        )

        saved = self._repo.add(db, notification)
        db.refresh(saved)

        if severity in ("critical", "high"):
            for channel in self._channels:
                if channel.channel_name != "internal":
                    try:
                        success = channel.send(title, message, severity, details or {})
                        if success:
                            saved.status = "sent"
                            saved.channel = channel.channel_name
                    except Exception:
                        saved.status = "failed"
                        saved.details = {**(saved.details or {}), "error": "channel_send_failed"}

        db.commit()
        return saved

    def notify_incident(self, db: Session, incident: Incident) -> Notification:
        """Создает уведомление для инцидента."""
        title = f"Security Incident: {incident.incident_type}"
        message = incident.description

        return self.create_notification(
            db=db,
            notification_type="incident",
            severity=incident.severity,
            title=title,
            message=message,
            incident_id=incident.id,
            event_id=incident.event_id,
            details=incident.details,
        )

    def notify_critical_event(self, db: Session, event: Event) -> Optional[Notification]:
        """Создает уведомление для критического события."""
        if event.severity != "critical":
            return None

        title = f"Critical Event: {event.event_type}"
        message = event.message

        return self.create_notification(
            db=db,
            notification_type="critical_event",
            severity="critical",
            title=title,
            message=message,
            event_id=event.id,
            details={"source_os": event.source_os, "source_category": event.source_category},
        )
