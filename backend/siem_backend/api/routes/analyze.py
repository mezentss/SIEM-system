from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from siem_backend.api.auth import require_admin
from siem_backend.data.db import get_db
from siem_backend.services.incident_service import IncidentService

router = APIRouter()


@router.post("/run")
def run_analysis(
    since_minutes: int = Query(default=60, ge=1, le=1440),
    db: Session = Depends(get_db),
    _ = Depends(require_admin),
) -> dict:
    found = IncidentService().run_analysis(db, since_minutes=since_minutes)
    return {"incidents_found": found}
