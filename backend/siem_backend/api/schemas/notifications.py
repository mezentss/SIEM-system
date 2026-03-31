from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class NotificationOut(BaseModel):
    """Уведомление для вывода в API."""
    
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: dt.datetime
    
    # Нормализованные поля (названия из справочников)
    notification_type: str = Field(description="Тип уведомления")
    severity: str = Field(description="Уровень серьёзности")
    
    title: str
    message: str
    incident_id: Optional[int]
    event_id: Optional[int]
    channel: str
    status: str
    details: dict = Field(default_factory=dict)
