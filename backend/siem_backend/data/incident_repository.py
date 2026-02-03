from __future__ import annotations

from typing import Sequence, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Incident


class IncidentRepository:
    def get_existing_event_type_pairs(
        self, db: Session, event_ids: Sequence[int]
    ) -> Set[Tuple[int, str]]:
        if not event_ids:
            return set()
        stmt = select(Incident.event_id, Incident.incident_type).where(
            Incident.event_id.in_(event_ids),
            Incident.event_id.isnot(None),
        )
        rows = db.execute(stmt).all()
        return {(eid, itype) for eid, itype in rows if eid is not None}

    def add_many(self, db: Session, incidents: Sequence[Incident]) -> int:
        if not incidents:
            return 0

        db.add_all(list(incidents))
        db.commit()
        return len(incidents)