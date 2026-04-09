from __future__ import annotations

import datetime as dt

from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from siem_backend.data.schemas import Base


# =============================================================================
# СПРАВОЧНИКИ (нормализованные данные)
# =============================================================================


class SourceOS(Base):
    """Справочник операционных систем — источников логов."""
    
    __tablename__ = "source_os"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    
    # Отношения
    events: Mapped[list["Event"]] = relationship("Event", back_populates="source_os_rel")

    def __repr__(self) -> str:
        return f"<SourceOS(name={self.name!r})>"


class SourceCategoryRef(Base):
    """Справочник категорий источников событий."""
    
    __tablename__ = "source_categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    
    # Отношения
    events: Mapped[list["Event"]] = relationship("Event", back_populates="source_category_rel")

    def __repr__(self) -> str:
        return f"<SourceCategoryRef(name={self.name!r})>"


class EventType(Base):
    """Справочник типов событий."""
    
    __tablename__ = "event_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )
    is_builtin: Mapped[bool] = mapped_column(Integer, default=1, index=True)
    
    # Отношения
    events: Mapped[list["Event"]] = relationship("Event", back_populates="event_type_rel")

    def __repr__(self) -> str:
        return f"<EventType(name={self.name!r})>"


class SeverityLevel(Base):
    """Справочник уровней серьёзности."""
    
    __tablename__ = "severity_levels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, index=True, default=0)
    description: Mapped[str] = mapped_column(Text, default="")
    
    # Отношения
    events: Mapped[list["Event"]] = relationship("Event", back_populates="severity_rel")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="severity_rel")
    notifications: Mapped[list["Notification"]] = relationship("Notification", back_populates="severity_rel")

    def __repr__(self) -> str:
        return f"<SeverityLevel(name={self.name!r}, rank={self.rank})>"


class IncidentType(Base):
    """Справочник типов инцидентов."""
    
    __tablename__ = "incident_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    default_severity_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("severity_levels.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Отношения
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="incident_type_rel")
    default_severity_rel: Mapped[Optional["SeverityLevel"]] = relationship(
        "SeverityLevel", 
        foreign_keys=[default_severity_id]
    )

    def __repr__(self) -> str:
        return f"<IncidentType(name={self.name!r})>"


class NotificationType(Base):
    """Справочник типов уведомлений."""
    
    __tablename__ = "notification_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    
    # Отношения
    notifications: Mapped[list["Notification"]] = relationship(
        "Notification", 
        back_populates="notification_type_rel"
    )

    def __repr__(self) -> str:
        return f"<NotificationType(name={self.name!r})>"


# =============================================================================
# ОСНОВНЫЕ ТАБЛИЦЫ (нормализованные)
# =============================================================================


class Event(Base):
    """События безопасности (нормализованная структура)."""
    
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    # ✅ Внешние ключи к справочникам (2НФ)
    source_os_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("source_os.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )
    source_category_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("source_categories.id", ondelete="RESTRICT"),
        index=True,
        default=1  # unknown
    )
    event_type_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("event_types.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )
    severity_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("severity_levels.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )

    message: Mapped[str] = mapped_column(Text)
    
    # ⚠️ raw_data оставлен только для отладки/аудита
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    # ✅ Отношения для удобных JOIN
    source_os_rel: Mapped["SourceOS"] = relationship("SourceOS", back_populates="events")
    source_category_rel: Mapped["SourceCategoryRef"] = relationship(
        "SourceCategoryRef", 
        back_populates="events"
    )
    event_type_rel: Mapped["EventType"] = relationship("EventType", back_populates="events")
    severity_rel: Mapped["SeverityLevel"] = relationship("SeverityLevel", back_populates="events")

    def __repr__(self) -> str:
        return f"<Event(id={self.id}, ts={self.ts}, severity={self.severity_rel.name if self.severity_rel else 'unknown'})>"


class Incident(Base):
    """Инциденты безопасности (нормализованная структура)."""
    
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    # ✅ Внешний ключ к типу инцидента (2НФ)
    incident_type_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("incident_types.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )
    
    # ✅ Внешний ключ к уровню серьёзности (2НФ)
    severity_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("severity_levels.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )
    
    # ✅ Внешний ключ к событию (с каскадом)
    event_id: Mapped[Optional[int]] = mapped_column(
        Integer, 
        ForeignKey("events.id", ondelete="SET NULL"),
        nullable=True, 
        index=True
    )

    description: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    # Статус инцидента
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    resolved_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ✅ Отношения
    incident_type_rel: Mapped["IncidentType"] = relationship(
        "IncidentType", 
        back_populates="incidents"
    )
    severity_rel: Mapped["SeverityLevel"] = relationship(
        "SeverityLevel", 
        back_populates="incidents"
    )
    event_rel: Mapped[Optional["Event"]] = relationship("Event", back_populates="incident_rel")

    def __repr__(self) -> str:
        return f"<Incident(id={self.id}, type={self.incident_type_rel.name if self.incident_type_rel else 'unknown'}, severity={self.severity_rel.name if self.severity_rel else 'unknown'})>"


class Notification(Base):
    """Уведомления (нормализованная структура)."""
    
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True, default=dt.datetime.utcnow)

    # ✅ Внешний ключ к типу уведомления (2НФ)
    notification_type_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("notification_types.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )
    
    # ✅ Внешний ключ к уровню серьёзности (2НФ)
    severity_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey("severity_levels.id", ondelete="RESTRICT"),
        index=True,
        nullable=False
    )

    title: Mapped[str] = mapped_column(String(256))
    message: Mapped[str] = mapped_column(Text)

    # ✅ Внешние ключи с каскадным удалением
    incident_id: Mapped[Optional[int]] = mapped_column(
        Integer, 
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=True, 
        index=True
    )
    event_id: Mapped[Optional[int]] = mapped_column(
        Integer, 
        ForeignKey("events.id", ondelete="CASCADE"),
        nullable=True, 
        index=True
    )

    channel: Mapped[str] = mapped_column(String(32), index=True, default="internal")
    status: Mapped[str] = mapped_column(String(16), index=True, default="pending")
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    # ✅ Отношения
    notification_type_rel: Mapped["NotificationType"] = relationship(
        "NotificationType", 
        back_populates="notifications"
    )
    severity_rel: Mapped["SeverityLevel"] = relationship(
        "SeverityLevel", 
        back_populates="notifications"
    )
    incident_rel: Mapped[Optional["Incident"]] = relationship(
        "Incident", 
        back_populates="notification_rel"
    )
    event_rel: Mapped[Optional["Event"]] = relationship(
        "Event", 
        back_populates="notification_rel"
    )

    def __repr__(self) -> str:
        return f"<Notification(id={self.id}, type={self.notification_type_rel.name if self.notification_type_rel else 'unknown'})>"


# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ТАБЛИЦЫ
# =============================================================================


class AnalysisRule(Base):
    """Правила анализа событий."""
    
    __tablename__ = "analysis_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
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
        onupdate=dt.datetime.utcnow,
    )

    def __repr__(self) -> str:
        return f"<AnalysisRule(name={self.name!r})>"


class SystemRun(Base):
    """Журнал запусков системы анализа."""
    
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

    def __repr__(self) -> str:
        return f"<SystemRun(id={self.id}, status={self.status})>"


class LogSource(Base):
    """Источники логов."""
    
    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")

    config: Mapped[dict] = mapped_column(JSON, default=dict)

    is_active: Mapped[int] = mapped_column(Integer, index=True, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=dt.datetime.utcnow,
    )

    def __repr__(self) -> str:
        return f"<LogSource(name={self.name!r}, type={self.source_type})>"


class RuleTrigger(Base):
    """Журнал срабатываний правил анализа."""
    
    __tablename__ = "rule_triggers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    rule_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("analysis_rules.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    incident_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("incidents.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    event_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("events.id", ondelete="SET NULL"),
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

    def __repr__(self) -> str:
        return f"<RuleTrigger(rule_id={self.rule_id}, incident_id={self.incident_id})>"


# =============================================================================
# ДОБАВЛЕНИЕ ОТНОШЕНИЙ (обратные связи)
# =============================================================================

# Добавляем обратные отношения для Event
Event.incident_rel = relationship(
    "Incident",
    back_populates="event_rel",
    uselist=False
)
Event.notification_rel = relationship(
    "Notification",
    back_populates="event_rel"
)

# Добавляем обратные отношения для Incident
Incident.notification_rel = relationship(
    "Notification",
    back_populates="incident_rel"
)
