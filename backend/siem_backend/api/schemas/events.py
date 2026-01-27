from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: dt.datetime
    source_os: str
    source_category: str
    event_type: str
    severity: str
    message: str
    # Человеко-читаемое описание события для отображения на фронтенде
    description: str = ""
    raw_data: dict
