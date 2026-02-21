from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.types import IncidentCandidate


class RepeatedNetworkErrorsRule(BaseRule):
    name = "repeated_network_errors"

    def __init__(self, threshold: int = 10, window_minutes: int = 10) -> None:
        self._threshold = threshold
        self._window_minutes = window_minutes

    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        stmt = (
            select(Event)
            .where(Event.ts >= since)
            .where(Event.ts <= until)
            .where(Event.event_type == "network")
        )
        events = db.execute(stmt).scalars().all()

        keywords = [
            "error",
            "failed",
            "refused",
            "timeout",
            "timed out",
            "unreachable",
            "socket",
        ]

        matched: List[Event] = []
        for e in events:
            msg = (e.message or "").lower()
            if any(k in msg for k in keywords):
                matched.append(e)

        count = len(matched)
        if count < self._threshold:
            return []

        # Определяем серьёзность на основе количества событий
        severity = "low"
        if count >= 200:
            severity = "critical"
        elif count >= 100:
            severity = "high"
        elif count >= 50:
            severity = "medium"
        elif count >= 10:
            severity = "low"

        last_event_id = matched[-1].id if matched else None

        description = (
            f"Repeated network-related errors detected: {count} events within last "
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
