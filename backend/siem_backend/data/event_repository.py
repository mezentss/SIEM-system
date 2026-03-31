from __future__ import annotations

from typing import Sequence, Set, Tuple

import datetime as dt
from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event, SourceOS


class EventRepository:
    """Репозиторий для работы с событиями."""
    
    def get_existing_signatures(
        self, db: Session, since: dt.datetime, until: dt.datetime
    ) -> Set[Tuple[dt.datetime, str, str]]:
        """
        Получает существующие сигнатуры событий за период.
        
        Args:
            db: Сессия БД
            since: Начало периода
            until: Конец периода
            
        Returns:
            Множество кортежей (timestamp, message, source_os_name)
        """
        stmt = select(Event.ts, Event.message, Event.source_os_id).where(
            Event.ts >= since,
            Event.ts <= until,
        )
        rows = db.execute(stmt).all()
        
        # Кэшируем названия ОС
        os_ids = {row[2] for row in rows if row[2] is not None}
        os_cache = {}
        if os_ids:
            os_stmt = select(SourceOS.id, SourceOS.name).where(SourceOS.id.in_(os_ids))
            for os_id, os_name in db.execute(os_stmt).all():
                os_cache[os_id] = os_name
        
        out: Set[Tuple[dt.datetime, str, str]] = set()
        for ts, message, source_os_id in rows:
            key_ts = ts.replace(microsecond=0) if hasattr(ts, "replace") else ts
            source_os_name = os_cache.get(source_os_id, "unknown") if source_os_id else "unknown"
            out.add((key_ts, message or "", source_os_name))
        return out

    def add_many(self, db: Session, events: Sequence[Event]) -> int:
        """
        Добавляет множество событий в БД.
        
        Args:
            db: Сессия БД
            events: Список событий для добавления
            
        Returns:
            Количество добавленных событий
        """
        if not events:
            return 0
        db.add_all(list(events))
        db.commit()
        return len(events)
