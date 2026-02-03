from __future__ import annotations

import datetime as dt
from typing import List, Optional

from sqlalchemy.orm import Session

from siem_backend.data.incident_repository import IncidentRepository
from siem_backend.data.models import Incident
from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.engine import RuleEngine
from siem_backend.services.analysis.rules.failed_logins import MultipleFailedLoginsRule
from siem_backend.services.analysis.rules.network_errors import RepeatedNetworkErrorsRule
from siem_backend.services.analysis.rules.service_crash import ServiceCrashOrRestartRule
from siem_backend.services.notifications import NotificationService


class IncidentService:
    def __init__(
        self,
        repo: Optional[IncidentRepository] = None,
        engine: Optional[RuleEngine] = None,
        notification_service: Optional[NotificationService] = None,
    ) -> None:
        self._repo = repo or IncidentRepository()
        self._engine = engine or RuleEngine(self._default_rules())
        self._notification_service = notification_service or NotificationService()

    def run_analysis(self, db: Session, since_minutes: int = 60) -> int:
        until = dt.datetime.utcnow()
        since = until - dt.timedelta(minutes=since_minutes)

        candidates = self._engine.run(db, since=since, until=until)
        event_ids = [c.event_id for c in candidates if c.event_id is not None]
        existing_pairs = self._repo.get_existing_event_type_pairs(db, event_ids)
        new_candidates = [
            c for c in candidates
            if c.event_id is None or (c.event_id, c.incident_type) not in existing_pairs
        ]
        incidents = [self._to_model(c) for c in new_candidates]
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
        return [
            MultipleFailedLoginsRule(),
            RepeatedNetworkErrorsRule(),
            ServiceCrashOrRestartRule(),
        ]

    def _to_model(self, candidate) -> Incident:
        return Incident(
            detected_at=candidate.detected_at,
            incident_type=candidate.incident_type,
            severity=candidate.severity,
            description=candidate.description,
            event_id=candidate.event_id,
            details=candidate.details,
        )