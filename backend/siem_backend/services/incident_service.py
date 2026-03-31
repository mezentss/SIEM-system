import datetime as dt
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.incident_repository import IncidentRepository
from siem_backend.data.models import Event, Incident, IncidentType, SeverityLevel
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.engine import RuleEngine
from siem_backend.services.analysis.rules.failed_logins import MultipleFailedLoginsRule
from siem_backend.services.analysis.rules.network_errors import RepeatedNetworkErrorsRule
from siem_backend.services.analysis.rules.service_crash import ServiceCrashOrRestartRule
from siem_backend.services.notifications import NotificationService

logger = logging.getLogger(__name__)


class IncidentService:
    """Сервис для работы с инцидентами."""
    
    def __init__(
        self,
        repo: Optional[IncidentRepository] = None,
        engine: Optional[RuleEngine] = None,
        notification_service: Optional[NotificationService] = None,
    ) -> None:
        self._repo = repo or IncidentRepository()
        self._engine = engine or RuleEngine(self._default_rules())
        self._notification_service = notification_service or NotificationService()
        
        # Кэш справочников
        self._incident_type_cache: Dict[str, int] = {}
        self._severity_cache: Dict[str, int] = {}

    def _load_reference_cache(self, db: Session) -> None:
        """Загружает кэш справочников."""
        if not self._incident_type_cache:
            for item in db.execute(select(IncidentType)).scalars().all():
                self._incident_type_cache[item.name] = item.id
        
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
        """
        Получает ID справочника по имени из кэша или БД.
        
        Args:
            db: Сессия БД
            model: Модель справочника
            cache: Кэш справочника
            name: Имя для поиска
            default_name: Имя по умолчанию
            
        Returns:
            ID записи в справочнике
        """
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

    def run_analysis(self, db: Session, since_minutes: int = 60) -> int:
        """
        Запускает анализ событий на наличие инцидентов.
        
        Args:
            db: Сессия БД
            since_minutes: Период анализа в минутах
            
        Returns:
            Количество найденных инцидентов
        """
        self._load_reference_cache(db)
        
        until = dt.datetime.utcnow()
        since = until - dt.timedelta(minutes=since_minutes)

        candidates = self._engine.run(db, since=since, until=until)
        event_ids = [c.event_id for c in candidates if c.event_id is not None]
        existing_pairs = self._repo.get_existing_event_type_pairs(db, event_ids)
        new_candidates = [
            c for c in candidates
            if c.event_id is None or (c.event_id, c.incident_type) not in existing_pairs
        ]

        recent_incident_types = self._repo.get_recent_incident_types(db, since_minutes=120)

        event_by_id: Dict[int, Event] = {}
        unique_event_ids = sorted({c.event_id for c in new_candidates if c.event_id is not None})
        if unique_event_ids:
            stmt = select(Event).where(Event.id.in_(unique_event_ids))
            events = db.execute(stmt).scalars().all()
            event_by_id = {e.id: e for e in events if e.id is not None}

        incidents = [self._to_model(db, c, event_by_id.get(c.event_id or -1)) for c in new_candidates]
        if not incidents:
            return 0
        saved_count = self._repo.add_many(db, incidents)

        for incident in incidents:
            try:
                self._notification_service.notify_incident(db, incident)
            except Exception:
                pass

        return saved_count

    def _default_rules(self) -> List[BaseRule]:
        """Возвращает правила анализа по умолчанию."""
        return [
            MultipleFailedLoginsRule(),
            RepeatedNetworkErrorsRule(),
            ServiceCrashOrRestartRule(),
        ]

    def _to_model(
        self, 
        db: Session, 
        candidate, 
        event: Optional[Event] = None
    ) -> Incident:
        """
        Преобразует кандидата в инцидент в модель БД.
        
        Args:
            db: Сессия БД
            candidate: Кандидат в инциденты
            event: Связанное событие (опционально)
            
        Returns:
            Модель инцидента для сохранения в БД
        """
        details: Dict[str, Any] = dict(candidate.details or {})

        if event is not None:
            raw = event.raw_data or {}
            process = raw.get("process") or ""
            service = raw.get("service") or ""
            application = raw.get("application") or ""

            if process:
                details.setdefault("process", process)
            if service:
                details.setdefault("service", service)
            if application:
                details.setdefault("application", application)

        # Получаем ID справочников
        incident_type_id = self._get_ref_id(
            db, IncidentType, self._incident_type_cache,
            candidate.incident_type, default_name="service_crash_or_restart"
        )
        
        severity_id = self._get_ref_id(
            db, SeverityLevel, self._severity_cache,
            candidate.severity, default_name="low"
        )

        return Incident(
            detected_at=candidate.detected_at,
            incident_type_id=incident_type_id,
            severity_id=severity_id,
            description=candidate.description,
            event_id=candidate.event_id,
            details=details,
        )

    def auto_resolve_inactive_incidents(self, db: Session, minutes: int = 60) -> int:
        """
        Автоматическое закрытие инцидентов без новых событий.

        Если за последние N минут не было новых событий того же типа,
        инцидент помечается как решённый.

        Args:
            db: Сессия базы данных
            minutes: Период безактивности в минутах (по умолчанию 60)

        Returns:
            Количество закрытых инцидентов
        """
        self._load_reference_cache(db)
        cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=minutes)

        # Находим активные инциденты, созданные до cutoff
        stmt = select(Incident).where(
            Incident.detected_at < cutoff,
            Incident.status != "resolved"
        )
        inactive_incidents = db.execute(stmt).scalars().all()

        resolved_count = 0
        for incident in inactive_incidents:
            # Получаем название типа инцидента для поиска событий
            incident_type_name = db.execute(
                select(IncidentType.name).where(IncidentType.id == incident.incident_type_id)
            ).scalar_one_or_none()
            
            if not incident_type_name:
                continue
            
            # Проверяем, были ли новые события для этого типа инцидента
            event_stmt = select(Event).where(
                Event.ts >= cutoff,
                Event.event_type_id == incident.incident_type_id
            )
            new_events = db.execute(event_stmt).scalars().first()

            # Если новых событий нет — закрываем инцидент
            if not new_events:
                incident.status = "resolved"
                incident.resolved_at = dt.datetime.utcnow()
                incident.resolved_by = "auto"
                incident.resolution_notes = "Auto-resolved: no new events in {} minutes".format(minutes)
                resolved_count += 1

        if resolved_count > 0:
            db.commit()
            logger.info(f"Auto-resolved {resolved_count} inactive incidents")

        return resolved_count

    def resolve_incident(
        self,
        db: Session,
        incident_id: int,
        username: str,
        notes: Optional[str] = None
    ) -> Optional[Incident]:
        """
        Ручное закрытие инцидента пользователем.
        
        Args:
            db: Сессия БД
            incident_id: ID инцидента
            username: Имя пользователя
            notes: Примечание к закрытию
            
        Returns:
            Закрытый инцидент или None
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            return None

        incident.status = "resolved"
        incident.resolved_at = dt.datetime.utcnow()
        incident.resolved_by = username
        incident.resolution_notes = notes or "Resolved manually"

        db.commit()
        db.refresh(incident)

        logger.info(f"Incident {incident_id} resolved by {username}")

        return incident

    def reopen_incident(
        self,
        db: Session,
        incident_id: int,
        username: str
    ) -> Optional[Incident]:
        """
        Повторное открытие закрытого инцидента.

        Args:
            db: Сессия базы данных
            incident_id: ID инцидента
            username: Имя пользователя, открывающего инцидент

        Returns:
            Открытый инцидент или None, если не найден
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            return None

        incident.status = "active"
        incident.resolved_at = None
        incident.resolved_by = None
        incident.resolution_notes = f"Reopened by {username}"

        db.commit()
        db.refresh(incident)

        logger.info(f"Incident {incident_id} reopened by {username}")

        return incident

    def get_incident_type_name(self, db: Session, incident: Incident) -> str:
        """
        Получает название типа инцидента.
        
        Args:
            db: Сессия БД
            incident: Инцидент
            
        Returns:
            Название типа инцидента
        """
        if incident.incident_type_rel:
            return incident.incident_type_rel.name
            
        stmt = select(IncidentType.name).where(IncidentType.id == incident.incident_type_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"

    def get_incident_severity_name(self, db: Session, incident: Incident) -> str:
        """
        Получает название уровня серьёзности инцидента.
        
        Args:
            db: Сессия БД
            incident: Инцидент
            
        Returns:
            Название уровня серьёзности
        """
        if incident.severity_rel:
            return incident.severity_rel.name
            
        stmt = select(SeverityLevel.name).where(SeverityLevel.id == incident.severity_id)
        return db.execute(stmt).scalar_one_or_none() or "unknown"

    def get_incidents_with_details(
        self,
        db: Session,
        limit: int = 50,
        offset: int = 0,
        severity_name: Optional[str] = None,
        incident_type_name: Optional[str] = None
    ) -> List[Incident]:
        """
        Получает инциденты с подробностями.
        
        Args:
            db: Сессия БД
            limit: Лимит записей
            offset: Смещение
            severity_name: Фильтр по серьёзности (опционально)
            incident_type_name: Фильтр по типу (опционально)
            
        Returns:
            Список инцидентов
        """
        self._load_reference_cache(db)
        
        stmt = select(Incident).order_by(Incident.detected_at.desc()).limit(limit).offset(offset)

        if severity_name:
            severity_id = self._severity_cache.get(severity_name.lower())
            if severity_id:
                stmt = stmt.where(Incident.severity_id == severity_id)

        if incident_type_name:
            incident_type_id = self._incident_type_cache.get(incident_type_name)
            if incident_type_id:
                stmt = stmt.where(Incident.incident_type_id == incident_type_id)

        return list(db.execute(stmt).scalars().all())
