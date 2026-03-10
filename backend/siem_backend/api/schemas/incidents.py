from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AdviceOut(BaseModel):
    title: str
    short: str
    full: str
    icon: str


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    detected_at: dt.datetime
    incident_type: str
    severity: str
    description: str
    friendly_description: str = ""
    event_id: Optional[int]
    details: dict
    advice: Optional[AdviceOut] = None
