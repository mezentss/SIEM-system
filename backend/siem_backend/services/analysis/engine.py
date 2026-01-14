from __future__ import annotations

import datetime as dt
from typing import Iterable, List, Sequence

from sqlalchemy.orm import Session

from siem_backend.services.analysis.base import BaseRule
from siem_backend.services.analysis.types import IncidentCandidate


class RuleEngine:
    def __init__(self, rules: Sequence[BaseRule]) -> None:
        self._rules = list(rules)

    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        results: List[IncidentCandidate] = []
        for rule in self._rules:
            results.extend(rule.run(db, since=since, until=until))
        return results

    @property
    def rules(self) -> Iterable[BaseRule]:
        return tuple(self._rules)
