from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from siem_backend.api.auth import get_current_user
from siem_backend.data.db import get_db
from siem_backend.data.models_user import User
from siem_backend.services.incident_service import IncidentService

router = APIRouter()


@router.post("/run")
def run_analysis(
    since_minutes: int = Query(default=60, ge=1, le=1440),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Запуск анализа инцидентов.
    
    Доступно для всех авторизованных пользователей (не только админов),
    чтобы обеспечить обновление данных в реальном времени для всех ролей.
    """
    found = IncidentService().run_analysis(db, since_minutes=since_minutes)
    return {"incidents_found": found}
