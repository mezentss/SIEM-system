from __future__ import annotations

from typing import Sequence

from sqlalchemy.orm import Session

from siem_backend.data.models import Incident


class IncidentRepository:
    def add_many(self, db: Session, incidents: Sequence[Incident]) -> int:
        if not incidents:
            return 0

        db.add_all(list(incidents))
        db.commit()
        return len(incidents)
