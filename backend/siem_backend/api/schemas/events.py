from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: dt.datetime
    source_os: str
    event_type: str
    severity: str
    message: str
    raw_data: dict
