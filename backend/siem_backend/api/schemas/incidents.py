from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AdviceOut(BaseModel):
    """Рекомендация по устранению инцидента."""
    
    title: str
    short: str
    full: str
    icon: str


class IncidentOut(BaseModel):
    """Инцидент для вывода в API."""
    
    model_config = ConfigDict(from_attributes=True)

    id: int
    detected_at: dt.datetime
    
    # Нормализованные поля (названия из справочников)
    incident_type: str = Field(description="Тип инцидента")
    severity: str = Field(description="Уровень серьёзности")
    
    description: str
    friendly_description: str = Field(default="", description="Дружественное описание")
    
    event_id: Optional[int]
    details: dict = Field(default_factory=dict)
    advice: Optional[AdviceOut] = None

    # Статус инцидента
    status: str = "active"
    resolved_at: Optional[dt.datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
