import datetime as dt
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event, EventType, SeverityLevel
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.types import IncidentCandidate


class MultipleFailedLoginsRule(BaseRule):
    """Правило обнаружения множественных неудачных попыток входа."""
    
    name = "multiple_failed_logins"

    def __init__(self, threshold: int = 5, window_minutes: int = 5) -> None:
        self._threshold = threshold
        self._window_minutes = window_minutes
        
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
                return 1  # Default ID
        return self._event_type_cache.get(name, 1)

    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        # Получаем ID типа события "authentication"
        auth_type_id = self._get_event_type_id(db, "authentication")
        
        stmt = (
            select(Event)
            .where(Event.ts >= since)
            .where(Event.ts <= until)
            .where(Event.event_type_id == auth_type_id)
        )
        events = db.execute(stmt).scalars().all()

        keywords = [
            "failed password",
            "failed login attempt",
            "authentication failure",
            "invalid password",
            "login failed",
        ]

        matched: List[Event] = []
        for e in events:
            msg = (e.message or "").lower()
            if any(k in msg for k in keywords):
                matched.append(e)

        count = len(matched)
        if count < self._threshold:
            return []

        severity = "warning"
        if count >= max(self._threshold * 2, 10):
            severity = "critical"

        last_event_id = matched[-1].id if matched else None

        description = (
            f"Multiple failed login attempts detected: {count} events within last "
            f"{int((until - since).total_seconds() // 60)} minutes."
        )

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
                    "window_minutes": self._window_minutes,
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                    "keywords": keywords,
                },
            )
        ]
