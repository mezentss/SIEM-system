from typing import Sequence, Set, Tuple

import datetime as dt
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Incident, IncidentType


class IncidentRepository:
    """Репозиторий для работы с инцидентами."""
    
    def get_existing_event_type_pairs(
        self, db: Session, event_ids: Sequence[int]
    ) -> Set[Tuple[int, str]]:
        """
        Получает пары (event_id, incident_type_name) для существующих инцидентов.
        
        Args:
            db: Сессия БД
            event_ids: Список ID событий
            
        Returns:
            Множество кортежей (event_id, incident_type_name)
        """
        if not event_ids:
            return set()
        stmt = select(Incident.event_id, Incident.incident_type_id).where(
            Incident.event_id.in_(event_ids),
            Incident.event_id.isnot(None),
        )
        rows = db.execute(stmt).all()
        
        # Получаем названия типов инцидентов
        type_ids = {row[1] for row in rows if row[1] is not None}
        type_cache = {}
        if type_ids:
            type_stmt = select(IncidentType.id, IncidentType.name).where(IncidentType.id.in_(type_ids))
            for type_id, type_name in db.execute(type_stmt).all():
                type_cache[type_id] = type_name
        
        result = set()
        for eid, type_id in rows:
            if eid is not None and type_id is not None:
                type_name = type_cache.get(type_id, f"type_{type_id}")
                result.add((eid, type_name))
        return result

    def add_many(self, db: Session, incidents: Sequence[Incident]) -> int:
        """
        Добавляет множество инцидентов в БД.
        
        Args:
            db: Сессия БД
            incidents: Список инцидентов для добавления
            
        Returns:
            Количество добавленных инцидентов
        """
        if not incidents:
            return 0

        db.add_all(list(incidents))
        db.commit()
        return len(incidents)

    def get_recent_incident_types(self, db: Session, since_minutes: int = 120) -> Set[str]:
        """
        Получает типы инцидентов за последние N минут.
        
        Args:
            db: Сессия БД
            since_minutes: Период в минутах
            
        Returns:
            Множество названий типов инцидентов
        """
        cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=since_minutes)
        stmt = select(Incident.incident_type_id).where(
            Incident.detected_at >= cutoff,
            Incident.incident_type_id.isnot(None),
        )
        rows = db.execute(stmt).all()
        
        type_ids = {row[0] for row in rows if row[0] is not None}
        if not type_ids:
            return set()
        
        type_stmt = select(IncidentType.name).where(IncidentType.id.in_(type_ids))
        return {row[0] for row in db.execute(type_stmt).all()}
