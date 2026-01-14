from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from typing import List

from sqlalchemy.orm import Session

from siem_backend.services.analysis.types import IncidentCandidate


class BaseRule(ABC):
    name: str

    @abstractmethod
    def run(self, db: Session, *, since: dt.datetime, until: dt.datetime) -> List[IncidentCandidate]:
        raise NotImplementedError
