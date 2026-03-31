from __future__ import annotations

import datetime as dt

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EventOut(BaseModel):
    """Событие для вывода в API."""
    
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: dt.datetime
    
    # Нормализованные поля (названия из справочников)
    source_os: str = Field(description="Операционная система источника")
    source_category: str = Field(description="Категория источника")
    event_type: str = Field(description="Тип события")
    severity: str = Field(description="Уровень серьёзности")
    
    message: str
    description: str = Field(default="", description="Человеко-читаемое описание")
    raw_data: dict = Field(default_factory=dict)


class EventCreate(BaseModel):
    """Событие для создания."""
    
    ts: dt.datetime
    source_os_id: int
    source_category_id: int
    event_type_id: int
    severity_id: int
    message: str
    raw_data: dict = Field(default_factory=dict)
