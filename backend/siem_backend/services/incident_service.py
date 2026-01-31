from __future__ import annotations

import datetime as dt
import re
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.incident_repository import IncidentRepository
from siem_backend.data.models import Event, Incident
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

        # Дедупликация для polling: не создаём одинаковые инциденты слишком часто.
        # Политика: не более 1 инцидента одного incident_type за последние 5 минут.
        dedupe_since = until - dt.timedelta(minutes=5)
        existing_types = set(
            db.execute(
                select(Incident.incident_type).where(Incident.detected_at >= dedupe_since)
            )
            .scalars()
            .all()
        )

        incidents = [
            self._to_model(db, c)
            for c in candidates
            if (c.incident_type not in existing_types)
        ]
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

    def _to_model(self, db: Session, candidate) -> Incident:
        details = dict(candidate.details or {})

        if candidate.event_id is not None:
            event = db.execute(select(Event).where(Event.id == candidate.event_id)).scalar_one_or_none()
            if event is not None:
                origin = self._extract_origin_from_event(event)
                for k, v in origin.items():
                    if v and k not in details:
                        details[k] = v

        return Incident(
            detected_at=candidate.detected_at,
            incident_type=candidate.incident_type,
            severity=candidate.severity,
            description=candidate.description,
            event_id=candidate.event_id,
            details=details,
        )

    def _extract_origin_from_event(self, event: Event) -> dict:
        """Best-effort извлечение приложения/службы из события.

        Храним в Incident.details, чтобы фронт мог показывать место обнаружения.
        """
        msg = event.message or ""
        raw = event.raw_data or {}
        raw_line = raw.get("raw_line") or ""
        text = raw_line if isinstance(raw_line, str) and raw_line else msg

        def is_meaningful_name(value: str) -> bool:
            v = (value or "").strip()
            if not v:
                return False
            if v.isdigit():
                return False
            # должно содержать хотя бы одну букву
            return re.search(r"[A-Za-zА-Яа-я]", v) is not None

        proc = ""
        service = ""

        # syslog full line: "Jan 16 12:34:56 host process[pid]: message"
        m_syslog = re.match(
            r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?(?P<host>\S+)\s+(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$",
            text,
        )
        if m_syslog:
            proc_candidate = m_syslog.group("proc")
            if is_meaningful_name(proc_candidate):
                proc = proc_candidate

        # fallback: "proc[pid]: message" or "proc: message"
        if not proc:
            m_proc = re.match(r"^\s*(?P<proc>[^\s:]+?)(?:\[\d+\])?:\s+.*$", text)
            proc_candidate = m_proc.group("proc") if m_proc else ""
            if is_meaningful_name(proc_candidate):
                proc = proc_candidate

        # sometimes message contains "...: <service>: ..." (best-effort)
        if ":" in text:
            parts = [p.strip() for p in text.split(":", 3)]
            # try to take token after first ':' if it looks like a unit name
            if len(parts) >= 2:
                candidate = parts[1]
                if is_meaningful_name(candidate) and " " not in candidate:
                    service = candidate

        if not service and is_meaningful_name(proc):
            service = proc

        return {
            "process": proc or "",
            "service": service or "",
            "application": service or "",
        }
