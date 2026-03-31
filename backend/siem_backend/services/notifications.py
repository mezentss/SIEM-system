import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib import request

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.core.config import settings
from siem_backend.data.models import Event, Incident, Notification, NotificationType, SeverityLevel
from siem_backend.data.notification_repository import NotificationRepository


class NotificationChannel(ABC):
    """Базовый класс канала уведомлений."""
    
    @abstractmethod
    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def channel_name(self) -> str:
        raise NotImplementedError


class TelegramChannel(NotificationChannel):
    """Telegram-канал для отправки уведомлений."""
    
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
    """Email-канал для отправки уведомлений."""
    
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
        # Заглушка для будущей реализации
        return True

    @property
    def channel_name(self) -> str:
        return "email"


class InternalChannel(NotificationChannel):
    """Внутренний канал для сохранения уведомлений в БД."""
    
    def send(self, title: str, message: str, severity: str, details: Dict[str, Any]) -> bool:
        return True

    @property
    def channel_name(self) -> str:
        return "internal"


def incident_text_ru(incident: Incident, db: Session) -> str:
    """
    Формирует текстовое описание инцидента на русском языке.
    
    Args:
        incident: Инцидент
        db: Сессия БД
        
    Returns:
        Текстовое описание
    """
    # Получаем название типа инцидента
    stmt = select(IncidentType.name).where(IncidentType.id == incident.incident_type_id)
    t = db.execute(stmt).scalar_one_or_none() or ""
    
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


def get_telegram_advice(severity_name: str) -> str:
    """
    Возвращает рекомендацию для Telegram-уведомления.
    
    Args:
        severity_name: Название уровня серьёзности
        
    Returns:
        Текст рекомендации
    """
    if severity_name == "critical":
        return """ЧТО ДЕЛАТЬ НЕМЕДЛЕННО:
1. Сохраните все открытые файлы
2. Не выключайте компьютер принудительно
3. Запишите код ошибки (если есть)
4. ЗВОНИТЕ: +7 (999) 123-45-67

⏰ Не откладывайте!"""
    elif severity_name == "high":
        return """ПЛАН ДЕЙСТВИЙ:
1. Сохраните все файлы
2. Закройте приложение с ошибками
3. Перезагрузите компьютер
4. Если проблема повторилась — звоните: +7 (999) 123-45-67

⏰ Решите в ближайшее время"""
    return ""


def critical_event_text_ru(event: Event, db: Session) -> str:
    """
    Формирует описание критического события.
    
    Args:
        event: Событие
        db: Сессия БД
        
    Returns:
        Текстовое описание
    """
    service = event.raw_data.get("service") if isinstance(event.raw_data, dict) else None
    if service:
        return f"Обнаружено критическое событие в службе {service}"
    
    # Получаем название категории источника
    if event.source_category_rel:
        return f"Обнаружено критическое событие в категории {event.source_category_rel.name}"
    
    # Получаем название типа события
    if event.event_type_rel:
        return f"Обнаружено критическое событие: {event.event_type_rel.name}"
    
    return "Обнаружено критическое событие"


class NotificationService:
    """Сервис уведомлений."""
    
    def __init__(
        self,
        repo: Optional[NotificationRepository] = None,
        channels: Optional[List[NotificationChannel]] = None,
    ) -> None:
        self._repo = repo or NotificationRepository()
        self._type_cache: Dict[str, int] = {}
        self._severity_cache: Dict[str, int] = {}
        
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

    def _load_reference_cache(self, db: Session) -> None:
        """Загружает кэш справочников."""
        if not self._type_cache:
            for item in db.execute(select(NotificationType)).scalars().all():
                self._type_cache[item.name] = item.id
        
        if not self._severity_cache:
            for item in db.execute(select(SeverityLevel)).scalars().all():
                self._severity_cache[item.name] = item.id

    def _get_ref_id(
        self, 
        db: Session, 
        model, 
        cache: Dict[str, int], 
        name: str,
        default_name: Optional[str] = None
    ) -> int:
        """Получает ID справочника по имени."""
        if name in cache:
            return cache[name]
        
        stmt = select(model).where(model.name == name)
        item = db.execute(stmt).scalar_one_or_none()
        
        if item:
            cache[name] = item.id
            return item.id
        
        if default_name and default_name in cache:
            return cache[default_name]
        
        stmt = select(model).limit(1)
        item = db.execute(stmt).scalar_one_or_none()
        if item:
            return item.id
            
        return 1

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
        """
        Создаёт уведомление в БД.
        
        Args:
            db: Сессия БД
            notification_type: Тип уведомления
            severity: Уровень серьёзности
            title: Заголовок
            message: Сообщение
            incident_id: ID связанного инцидента
            event_id: ID связанного события
            details: Дополнительные данные
            
        Returns:
            Сохранённое уведомление
        """
        self._load_reference_cache(db)
        
        notification_type_id = self._get_ref_id(
            db, NotificationType, self._type_cache,
            notification_type, default_name="incident"
        )
        
        severity_id = self._get_ref_id(
            db, SeverityLevel, self._severity_cache,
            severity, default_name="low"
        )
        
        notification = Notification(
            notification_type_id=notification_type_id,
            severity_id=severity_id,
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
        
        # Отправка через внешние каналы
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
        """
        Отправляет уведомление об инциденте.
        
        Args:
            db: Сессия БД
            incident: Инцидент
            
        Returns:
            Созданное уведомление
        """
        # Получаем название серьёзности
        severity_name = db.execute(
            select(SeverityLevel.name).where(SeverityLevel.id == incident.severity_id)
        ).scalar_one_or_none() or "low"
        
        text = incident_text_ru(incident, db)
        telegram_advice = get_telegram_advice(severity_name)
        message_for_telegram = f"{text}\n\n{telegram_advice}" if telegram_advice else text
        
        return self.create_notification(
            db=db,
            notification_type="incident",
            severity=severity_name,
            title=text,
            message=message_for_telegram,
            incident_id=incident.id,
            event_id=incident.event_id,
            details=incident.details,
        )

    def notify_critical_event(self, db: Session, event: Event) -> Optional[Notification]:
        """
        Отправляет уведомление о критическом событии.
        
        Args:
            db: Сессия БД
            event: Событие
            
        Returns:
            Созданное уведомление или None
        """
        # Проверяем серьёзность через связь
        severity_name = None
        if event.severity_rel:
            severity_name = event.severity_rel.name
        else:
            stmt = select(SeverityLevel.name).where(SeverityLevel.id == event.severity_id)
            severity_name = db.execute(stmt).scalar_one_or_none()
        
        if severity_name != "critical":
            return None
            
        text = critical_event_text_ru(event, db)
        return self.create_notification(
            db=db,
            notification_type="critical_event",
            severity="critical",
            title=text,
            message=text,
            event_id=event.id,
            details={"source_os": event.source_os_id, "source_category": event.source_category_id},
        )

    def get_severity_name(self, db: Session, notification: Notification) -> str:
        """
        Получает название уровня серьёзности уведомления.

        Args:
            db: Сессия БД
            notification: Уведомление

        Returns:
            Название уровня серьёзности
        """
        if notification.severity_rel:
            return notification.severity_rel.name

        stmt = select(SeverityLevel.name).where(SeverityLevel.id == notification.severity_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"

    def get_notification_type_name(self, db: Session, notification: Notification) -> str:
        """
        Получает название типа уведомления.

        Args:
            db: Сессия БД
            notification: Уведомление

        Returns:
            Название типа уведомления
        """
        if notification.notification_type_rel:
            return notification.notification_type_rel.name

        stmt = select(NotificationType.name).where(NotificationType.id == notification.notification_type_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"
