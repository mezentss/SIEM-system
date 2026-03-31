import datetime as dt
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event, EventType
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.types import IncidentCandidate


class ServiceCrashOrRestartRule(BaseRule):
    """Правило обнаружения сбоев или перезапусков служб."""
    
    name = "service_crash_or_restart"

    def __init__(self, threshold: int = 1) -> None:
        self._threshold = threshold
        
        # Кэш для справочников
        self._event_type_cache: Dict[str, int] = {}

    def _get_event_type_id(self, db: Session, name: str) -> int:
        """Получает ID типа события по названию."""
        if name not in self._event_type_cache:
            stmt = select(EventType.id).where(EventType.name == name)
            result = db.execute(stmt).scalar_one_or_none()
            if result:
                self._event_type_cache[name] = result
            else:
                return 1
        return self._event_type_cache.get(name, 1)

    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        # Получаем ID типа события "service"
        service_type_id = self._get_event_type_id(db, "service")
        
        stmt = (
            select(Event)
            .where(Event.ts >= since)
            .where(Event.ts <= until)
            .where(Event.event_type_id == service_type_id)
        )
        events = db.execute(stmt).scalars().all()

        keywords = [
            "crash",
            "terminated",
            "panic",
            "exited",
            "restart",
        ]

        matched: List[Event] = []
        for e in events:
            msg = (e.message or "").lower()
            if any(k in msg for k in keywords):
                matched.append(e)

        count = len(matched)
        if count < self._threshold:
            return []

        severity = "low"
        if count >= 100:
            severity = "critical"
        elif count >= 50:
            severity = "high"
        elif count >= 10:
            severity = "medium"
        elif count >= 3:
            severity = "low"

        last_event_id = matched[-1].id if matched else None
        description = f"Service crash/restart indicators detected: {count} events."

        return [
            IncidentCandidate(
                incident_type=self.name,
                severity=severity,
                description=description,
                detected_at=until,
                event_id=last_event_id,
                details={
                    "count": count,
                    "threshold": self._threshold,
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                    "keywords": keywords,
                },
            )
        ]
