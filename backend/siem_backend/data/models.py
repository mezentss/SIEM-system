from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, Integer, String, Text
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
