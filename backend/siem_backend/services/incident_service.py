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


class IncidentService:
    def __init__(
        self,
        repo: Optional[IncidentRepository] = None,
        engine: Optional[RuleEngine] = None,
    ) -> None:
        self._repo = repo or IncidentRepository()
        self._engine = engine or RuleEngine(self._default_rules())

    def run_analysis(self, db: Session, since_minutes: int = 60) -> int:
        until = dt.datetime.utcnow()
        since = until - dt.timedelta(minutes=since_minutes)

        candidates = self._engine.run(db, since=since, until=until)
        incidents = [self._to_model(c) for c in candidates]
        return self._repo.add_many(db, incidents)

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
