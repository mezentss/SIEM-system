from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: dt.datetime
    notification_type: str
    severity: str
    title: str
    message: str
    incident_id: Optional[int]
    event_id: Optional[int]
    channel: str
    status: str
    details: dict
