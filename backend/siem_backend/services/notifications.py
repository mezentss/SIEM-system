from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib import request

from sqlalchemy.orm import Session

from siem_backend.core.config import settings
from siem_backend.data.models import Event, Incident, Notification
from siem_backend.data.notification_repository import NotificationRepository


class NotificationChannel(ABC):
    @abstractmethod
    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def channel_name(self) -> str:
        raise NotImplementedError


class TelegramChannel(NotificationChannel):
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id

    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        if not self._bot_token or not self._chat_id:
            return False
        text = f"{title}"
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    @property
    def channel_name(self) -> str:
        return "telegram"


class EmailChannel(NotificationChannel):
    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        from_email: Optional[str] = None,
        to_email: Optional[str] = None,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._from_email = from_email
        self._to_email = to_email

    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        return True

    @property
    def channel_name(self) -> str:
        return "email"


class InternalChannel(NotificationChannel):
    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        return True

    @property
    def channel_name(self) -> str:
        return "internal"


def incident_text_ru(incident: Incident) -> str:
    t = incident.incident_type or ""
    details = incident.details or {}
    if t == "multiple_failed_logins":
        return "Обнаружены множественные неуспешные попытки входа"
    if t == "repeated_network_errors":
        count = details.get("events_count")
        window_minutes = details.get("window_minutes", 60)
        if count is not None:
            return f"Обнаружены повторяющиеся сетевые ошибки: {count} событий за последние {window_minutes} минут"
        return "Обнаружены повторяющиеся сетевые ошибки"
    if t == "service_crash_or_restart":
        service = details.get("service") or details.get("process") or details.get("program")
        if service:
            return f"Обнаружен сбой или перезапуск службы {service}"
        return "Обнаружен сбой или перезапуск службы"
    if incident.description:
        return f"Обнаружен инцидент безопасности: {incident.description}"
    if t:
        return f"Обнаружен инцидент безопасности: {t}"
    return "Обнаружен инцидент безопасности"


def critical_event_text_ru(event: Event) -> str:
    service = event.raw_data.get("service") if isinstance(event.raw_data, dict) else None
    if service:
        return f"Обнаружено критическое событие в службе {service}"
    if event.source_category:
        return f"Обнаружено критическое событие в категории {event.source_category}"
    if event.event_type:
        return f"Обнаружено критическое событие: {event.event_type}"
    return "Обнаружено критическое событие"


class NotificationService:
    def __init__(
        self,
        repo: Optional[NotificationRepository] = None,
        channels: Optional[List[NotificationChannel]] = None,
    ) -> None:
        self._repo = repo or NotificationRepository()
        if channels is not None:
            self._channels = channels
        else:
            base_channels: List[NotificationChannel] = [InternalChannel()]
            if settings.telegram_bot_token and settings.telegram_chat_id:
                base_channels.append(
                    TelegramChannel(
                        bot_token=settings.telegram_bot_token,
                        chat_id=settings.telegram_chat_id,
                    )
                )
            self._channels = base_channels

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
        text = incident_text_ru(incident)
        return self.create_notification(
            db=db,
            notification_type="incident",
            severity=incident.severity,
            title=text,
            message=text,
            incident_id=incident.id,
            event_id=incident.event_id,
            details=incident.details,
        )

    def notify_critical_event(self, db: Session, event: Event) -> Optional[Notification]:
        if event.severity != "critical":
            return None
        text = critical_event_text_ru(event)
        return self.create_notification(
            db=db,
            notification_type="critical_event",
            severity="critical",
            title=text,
            message=text,
            event_id=event.id,
            details={"source_os": event.source_os, "source_category": event.source_category},
        )