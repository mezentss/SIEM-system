from __future__ import annotations

import datetime as dt
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.event_repository import EventRepository
from siem_backend.data.models import (
    Event, 
    EventType, 
    SeverityLevel, 
    SourceCategoryRef, 
    SourceOS
)
from siem_backend.services.normalization import NormalizedEvent
from siem_backend.services.notifications import NotificationService


class EventService:
    """Сервис для работы с событиями."""
    
    def __init__(
        self,
        repo: Optional[EventRepository] = None,
        notification_service: Optional[NotificationService] = None,
    ) -> None:
        self._repo = repo or EventRepository()
        self._notification_service = notification_service or NotificationService()
        
        # Кэш справочников для производительности
        self._source_os_cache: Dict[str, int] = {}
        self._source_category_cache: Dict[str, int] = {}
        self._event_type_cache: Dict[str, int] = {}
        self._severity_cache: Dict[str, int] = {}

    def _load_reference_cache(self, db: Session) -> None:
        """Загружает кэш справочников."""
        if not self._source_os_cache:
            for item in db.execute(select(SourceOS)).scalars().all():
                self._source_os_cache[item.name] = item.id
        
        if not self._source_category_cache:
            for item in db.execute(select(SourceCategoryRef)).scalars().all():
                self._source_category_cache[item.name] = item.id
        
        if not self._event_type_cache:
            for item in db.execute(select(EventType)).scalars().all():
                self._event_type_cache[item.name] = item.id
        
        if not self._severity_cache:
            for item in db.execute(select(SeverityLevel)).scalars().all():
                self._severity_cache[item.name] = item.id

    def _get_or_create_ref_id(
        self, 
        db: Session, 
        model, 
        cache: Dict[str, int], 
        name: str,
        default_name: Optional[str] = None
    ) -> int:
        """
        Получает ID справочника по имени из кэша или БД.
        
        Args:
            db: Сессия БД
            model: Модель справочника
            cache: Кэш справочника
            name: Имя для поиска
            default_name: Имя по умолчанию, если не найдено
            
        Returns:
            ID записи в справочнике
        """
        # Проверяем кэш
        if name in cache:
            return cache[name]
        
        # Ищем в БД
        stmt = select(model).where(model.name == name)
        item = db.execute(stmt).scalar_one_or_none()
        
        if item:
            cache[name] = item.id
            return item.id
        
        # Если не найдено и есть default_name — используем его
        if default_name and default_name in cache:
            return cache[default_name]
        
        # Возвращаем первый доступный ID из справочника
        stmt = select(model).limit(1)
        item = db.execute(stmt).scalar_one_or_none()
        if item:
            return item.id
            
        # Если справочник пуст — возвращаем 1 (будет использован при вставке)
        return 1

    def save_normalized_events(self, db: Session, events: List[NormalizedEvent]) -> int:
        """
        Сохраняет нормализованные события в БД.
        
        Args:
            db: Сессия БД
            events: Список нормализованных событий
            
        Returns:
            Количество сохранённых событий
        """
        # Загружаем кэш справочников
        self._load_reference_cache(db)
        
        to_save = [self._to_model(db, e) for e in events]
        if not to_save:
            return 0
            
        since = min(e.ts for e in to_save)
        until = max(e.ts for e in to_save)
        existing = self._repo.get_existing_signatures(db, since, until)
        
        unique: List[Event] = []
        for e in to_save:
            key_ts = e.ts.replace(microsecond=0) if hasattr(e.ts, "replace") else e.ts
            key = (key_ts, e.message or "", e.source_os_rel.name if e.source_os_rel else "")
            if key not in existing:
                unique.append(e)
                existing.add(key)
                
        if not unique:
            return 0
            
        saved_count = self._repo.add_many(db, unique)
        
        # Уведомления о критических событиях
        for event_model in unique:
            severity_name = db.execute(
                select(SeverityLevel.name).where(SeverityLevel.id == event_model.severity_id)
            ).scalar_one_or_none()
            
            if severity_name == "critical":
                try:
                    self._notification_service.notify_critical_event(db, event_model)
                except Exception:
                    pass
                    
        return saved_count

    def _to_model(self, db: Session, event: NormalizedEvent) -> Event:
        """
        Преобразует нормализованное событие в модель БД.
        
        Args:
            db: Сессия БД
            event: Нормализованное событие
            
        Returns:
            Модель события для сохранения в БД
        """
        ts = self._parse_ts(event.ts)
        
        # Получаем ID справочников
        source_os_id = self._get_or_create_ref_id(
            db, SourceOS, self._source_os_cache, 
            event.source_os, default_name="mock"
        )
        
        source_category_id = self._get_or_create_ref_id(
            db, SourceCategoryRef, self._source_category_cache,
            event.source_category, default_name="os"
        )
        
        event_type_id = self._get_or_create_ref_id(
            db, EventType, self._event_type_cache,
            event.event_type, default_name="system"
        )
        
        severity_id = self._get_or_create_ref_id(
            db, SeverityLevel, self._severity_cache,
            event.severity, default_name="low"
        )
        
        return Event(
            ts=ts,
            source_os_id=source_os_id,
            source_category_id=source_category_id,
            event_type_id=event_type_id,
            severity_id=severity_id,
            message=event.message,
            raw_data=event.raw_data,
        )

    def _parse_ts(self, ts: str) -> dt.datetime:
        """
        Парсит временную метку из строки.
        
        Args:
            ts: Временная метка в формате ISO
            
        Returns:
            datetime объект в UTC
        """
        try:
            parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return dt.datetime.utcnow()
            
        if parsed.tzinfo is None:
            return parsed
            
        return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)

    def get_events_by_severity(
        self, 
        db: Session, 
        severity_name: str, 
        limit: int = 50, 
        offset: int = 0
    ) -> List[Event]:
        """
        Получает события по уровню серьёзности.
        
        Args:
            db: Сессия БД
            severity_name: Название уровня серьёзности
            limit: Лимит записей
            offset: Смещение
            
        Returns:
            Список событий
        """
        self._load_reference_cache(db)
        severity_id = self._severity_cache.get(severity_name.lower())
        
        if not severity_id:
            return []
            
        stmt = (
            select(Event)
            .where(Event.severity_id == severity_id)
            .order_by(Event.ts.desc())
            .limit(limit)
            .offset(offset)
        )
        
        return list(db.execute(stmt).scalars().all())

    def get_event_severity_name(self, db: Session, event: Event) -> str:
        """
        Получает название уровня серьёзности события.
        
        Args:
            db: Сессия БД
            event: Событие
            
        Returns:
            Название уровня серьёзности
        """
        if event.severity_rel:
            return event.severity_rel.name
            
        stmt = select(SeverityLevel.name).where(SeverityLevel.id == event.severity_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"

    def get_event_type_name(self, db: Session, event: Event) -> str:
        """
        Получает название типа события.
        
        Args:
            db: Сессия БД
            event: Событие
            
        Returns:
            Название типа события
        """
        if event.event_type_rel:
            return event.event_type_rel.name
            
        stmt = select(EventType.name).where(EventType.id == event.event_type_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"

    def get_source_os_name(self, db: Session, event: Event) -> str:
        """
        Получает название ОС источника.
        
        Args:
            db: Сессия БД
            event: Событие
            
        Returns:
            Название ОС
        """
        if event.source_os_rel:
            return event.source_os_rel.name
            
        stmt = select(SourceOS.name).where(SourceOS.id == event.source_os_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"
