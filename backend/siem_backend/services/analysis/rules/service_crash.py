from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.types import IncidentCandidate


class ServiceCrashOrRestartRule(BaseRule):
    name = "service_crash_or_restart"

    def __init__(self, threshold: int = 1) -> None:
        self._threshold = threshold

    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        stmt = select(Event).where(Event.ts >= since).where(Event.ts <= until)
        events = db.execute(stmt).scalars().all()

        keywords = [
            "crash",
            "terminated",
            "panic",
            "exited",
            "restart",
            "launchd",
        ]

        matched: List[Event] = []
        for e in events:
            msg = (e.message or "").lower()
            if any(k in msg for k in keywords):
                matched.append(e)

        count = len(matched)
        if count < self._threshold:
            return []

        last_event_id = matched[-1].id if matched else None
        description = f"Service crash/restart indicators detected: {count} events."

        return [
            IncidentCandidate(
                incident_type=self.name,
                severity="critical",
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
