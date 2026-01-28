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
    source_category: Mapped[str] = mapped_column(String(32), index=True, default="unknown")
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


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    notification_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    message: Mapped[str] = mapped_column(Text)

    incident_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    event_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("events.id"), nullable=True, index=True)

    channel: Mapped[str] = mapped_column(String(32), index=True, default="internal")
    status: Mapped[str] = mapped_column(String(16), index=True, default="pending")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class EventType(Base):
    __tablename__ = "event_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )
    is_builtin: Mapped[bool] = mapped_column(Integer, default=1, index=True)


class SeverityLevel(Base):
    __tablename__ = "severity_levels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    # Чем больше rank, тем критичнее уровень
    rank: Mapped[int] = mapped_column(Integer, index=True, default=0)
    description: Mapped[str] = mapped_column(Text, default="")


class SourceCategoryRef(Base):
    """
    Справочник категорий источников событий (os, service, user_process и т.д.).
    Имя выбрано SourceCategoryRef, чтобы не конфликтовать с полем Event.source_category.
    """

    __tablename__ = "source_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")


class AnalysisRule(Base):
    """
    Метаданные правил анализа (пороговые значения, окна и т.п.).
    Текущая реализация правил их не использует, но таблица нужна для расширения.
    """

    __tablename__ = "analysis_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")

    enabled: Mapped[int] = mapped_column(Integer, index=True, default=1)

    threshold: Mapped[int] = mapped_column(Integer, default=0)
    window_minutes: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )


class SystemRun(Base):
    """
    Запуски анализа (meta-информация для аудита и отладки).
    На текущий анализ не влияет.
    """

    __tablename__ = "system_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )
    finished_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )

    status: Mapped[str] = mapped_column(String(32), index=True, default="completed")
    rules_executed: Mapped[int] = mapped_column(Integer, default=0)
    incidents_found: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class LogSource(Base):
    """
    Источники логов (файлы, системные журналы, mock-источники и т.п.).
    """

    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    description: Mapped[str] = mapped_column(Text, default="")

    # Дополнительная конфигурация (пути, параметры подключения и т.п.)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    is_active: Mapped[int] = mapped_column(Integer, index=True, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )


class RuleTrigger(Base):
    """
    Связка "правило — инцидент — событие": кто и когда сработал.
    Не используется текущей логикой, но готово для расширения.
    """

    __tablename__ = "rule_triggers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    rule_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("analysis_rules.id"),
        index=True,
        nullable=False,
    )
    incident_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("incidents.id"),
        index=True,
        nullable=True,
    )
    event_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("events.id"),
        index=True,
        nullable=True,
    )

    triggered_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )

    severity_at_trigger: Mapped[str] = mapped_column(String(16), index=True, default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

