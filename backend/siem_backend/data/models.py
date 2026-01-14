from __future__ import annotations

import datetime as dt

from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from siem_backend.data.db import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    source_os: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)

    message: Mapped[str] = mapped_column(Text)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    incident_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    description: Mapped[str] = mapped_column(Text)

    event_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("events.id"), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
