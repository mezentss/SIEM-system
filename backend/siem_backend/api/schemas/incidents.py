from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detected_at: dt.datetime
    incident_type: str
    severity: str
    # Техническое описание (как сформировано правилом анализа)
    description: str
    # Дополнительное человеко-читаемое описание для фронтенда
    friendly_description: str = ""
    event_id: Optional[int]
    details: dict
