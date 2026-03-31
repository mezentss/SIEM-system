from __future__ import annotations

from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import (
    AnalysisRule,
    EventType,
    IncidentType,
    LogSource,
    NotificationType,
    SeverityLevel,
    SourceCategoryRef,
    SourceOS,
)


def _ensure_by_name(
    db: Session,
    model,
    rows: Sequence[dict],
    *,
    name_field: str = "name",
) -> int:
    """
    Добавляет записи в справочник только если они отсутствуют.
    
    Args:
        db: Сессия БД
        model: Модель SQLAlchemy
        rows: Список словарей с данными
        name_field: Имя поля для проверки уникальности
        
    Returns:
        Количество добавленных записей
    """
    if not rows:
        return 0

    name_attr = getattr(model, name_field)
    existing_names: set[str] = set(
        db.execute(select(name_attr)).scalars().all()
    )

    to_add = []
    for row in rows:
        name = row.get(name_field)
        if not name or name in existing_names:
            continue
        to_add.append(model(**row))

    if not to_add:
        return 0

    db.add_all(to_add)
    return len(to_add)


def init_reference_data(db: Session) -> None:
    """
    Инициализирует нормализованные справочные данные.
    
    Безопасна при повторных вызовах:
    - добавляет только отсутствующие записи;
    - не чистит таблицы;
    - не меняет существующие строки.
    
    Справочники:
    1. SourceOS — операционные системы
    2. SeverityLevel — уровни серьёзности
    3. SourceCategoryRef — категории источников
    4. EventType — типы событий
    5. IncidentType — типы инцидентов
    6. NotificationType — типы уведомлений
    7. AnalysisRule — правила анализа
    8. LogSource — источники логов
    """
    created_total = 0

    # ==========================================================================
    # 1. SourceOS: macos, linux, windows, mock
    # ==========================================================================
    source_os_rows: list[dict] = [
        {"name": "macos", "description": "macOS Unified Log"},
        {"name": "linux", "description": "Linux Syslog"},
        {"name": "windows", "description": "Windows Event Log"},
        {"name": "mock", "description": "Mock Generator для тестирования"},
    ]
    created_total += _ensure_by_name(db, SourceOS, source_os_rows)

    # ==========================================================================
    # 2. SeverityLevel: info, low, medium, high, critical
    # ==========================================================================
    severity_rows: list[dict] = [
        {"name": "info", "rank": 0, "description": "Информационные события"},
        {"name": "low", "rank": 1, "description": "Низкий уровень важности"},
        {"name": "medium", "rank": 2, "description": "Средний уровень важности"},
        {"name": "high", "rank": 3, "description": "Высокий уровень важности"},
        {"name": "critical", "rank": 4, "description": "Критический уровень важности"},
    ]
    created_total += _ensure_by_name(db, SeverityLevel, severity_rows)

    # ==========================================================================
    # 3. SourceCategoryRef: os, auth, network, system_service, user_process
    # ==========================================================================
    source_category_rows: list[dict] = [
        {"name": "os", "description": "События операционной системы"},
        {"name": "auth", "description": "События аутентификации и авторизации"},
        {"name": "network", "description": "Сетевые события и соединения"},
        {"name": "system_service", "description": "Системные службы и демоны"},
        {"name": "user_process", "description": "Пользовательские процессы и приложения"},
    ]
    created_total += _ensure_by_name(db, SourceCategoryRef, source_category_rows)

    # ==========================================================================
    # 4. EventType: auth_failed, auth_success, network_error, service_crash
    # ==========================================================================
    event_type_rows: list[dict] = [
        {
            "name": "auth_failed",
            "description": "Неуспешная попытка аутентификации пользователя",
            "is_builtin": 1,
        },
        {
            "name": "auth_success",
            "description": "Успешная аутентификация пользователя",
            "is_builtin": 1,
        },
        {
            "name": "network_error",
            "description": "Ошибка сетевого соединения или нестабильность сети",
            "is_builtin": 1,
        },
        {
            "name": "service_crash",
            "description": "Сбой или аварийное завершение службы",
            "is_builtin": 1,
        },
        {
            "name": "authentication",
            "description": "События аутентификации (общий тип)",
            "is_builtin": 1,
        },
        {
            "name": "network",
            "description": "Сетевые события (общий тип)",
            "is_builtin": 1,
        },
        {
            "name": "service",
            "description": "События служб (общий тип)",
            "is_builtin": 1,
        },
        {
            "name": "process",
            "description": "События процессов (общий тип)",
            "is_builtin": 1,
        },
        {
            "name": "system",
            "description": "Системные события (общий тип)",
            "is_builtin": 1,
        },
        {
            "name": "macos_unified_log",
            "description": "События из macOS Unified Log",
            "is_builtin": 1,
        },
    ]
    created_total += _ensure_by_name(db, EventType, event_type_rows)

    # ==========================================================================
    # 5. IncidentType: multiple_failed_logins, repeated_network_errors, service_crash
    # ==========================================================================
    # Сначала получаем ID уровней серьёзности для default_severity_id
    severity_map = {
        row["name"]: row["name"] 
        for row in severity_rows
    }
    
    incident_type_rows: list[dict] = [
        {
            "name": "multiple_failed_logins",
            "description": "Обнаружение множественных неуспешных попыток входа за короткий период",
        },
        {
            "name": "repeated_network_errors",
            "description": "Повторяющиеся сетевые ошибки, указывающие на возможную атаку или неисправность",
        },
        {
            "name": "service_crash_or_restart",
            "description": "Частые сбои или перезапуски служб",
        },
    ]
    created_total += _ensure_by_name(db, IncidentType, incident_type_rows)

    # ==========================================================================
    # 6. NotificationType: incident, critical_event
    # ==========================================================================
    notification_type_rows: list[dict] = [
        {
            "name": "incident",
            "description": "Уведомление об инциденте безопасности",
        },
        {
            "name": "critical_event",
            "description": "Уведомление о критическом событии",
        },
    ]
    created_total += _ensure_by_name(db, NotificationType, notification_type_rows)

    # ==========================================================================
    # 7. AnalysisRule: правила анализа
    # ==========================================================================
    analysis_rule_rows: list[dict] = [
        {
            "name": "multiple_failed_logins",
            "description": "Обнаружение множественных неуспешных попыток входа за короткий период.",
            "enabled": 1,
            "threshold": 5,
            "window_minutes": 5,
        },
        {
            "name": "repeated_network_errors",
            "description": "Повторяющиеся сетевые ошибки, указывающие на возможную атаку или неисправность.",
            "enabled": 1,
            "threshold": 10,
            "window_minutes": 10,
        },
        {
            "name": "service_crash_or_restart",
            "description": "Частые сбои или перезапуски служб.",
            "enabled": 1,
            "threshold": 1,
            "window_minutes": 60,
        },
    ]
    created_total += _ensure_by_name(db, AnalysisRule, analysis_rule_rows)

    # ==========================================================================
    # 8. LogSource: macos_syslog, linux_syslog, file_log
    # ==========================================================================
    log_source_rows: list[dict] = [
        {
            "name": "macos_syslog",
            "source_type": "syslog",
            "description": "Системный журнал macOS (log show).",
            "config": {"platform": "macos"},
            "is_active": 1,
        },
        {
            "name": "linux_syslog",
            "source_type": "syslog",
            "description": "Системный журнал Linux (/var/log/syslog или journalctl).",
            "config": {"platform": "linux"},
            "is_active": 0,
        },
        {
            "name": "file_log",
            "source_type": "file",
            "description": "Локальный файл логов (например, backend/logs/system.log).",
            "config": {"default_path": "./logs/system.log"},
            "is_active": 1,
        },
    ]
    created_total += _ensure_by_name(db, LogSource, log_source_rows)

    if created_total:
        db.commit()
    else:
        # на всякий случай откатываем транзакцию без изменений
        db.rollback()
