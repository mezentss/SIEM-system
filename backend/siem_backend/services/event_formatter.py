from sqlalchemy import select
from sqlalchemy.orm import Session

from siem_backend.data.models import Event, Incident, EventType, IncidentType, SeverityLevel, SourceCategoryRef


def format_event_description(event: Event, db: Session = None) -> str:
    """
    Формирует человеко-читаемое описание события.
    
    Args:
        event: Событие
        db: Сессия БД (опционально, для получения названий справочников)
        
    Returns:
        Описание события
    """
    # Получаем названия из связанных объектов или через БД
    event_type_name = ""
    if event.event_type_rel:
        event_type_name = event.event_type_rel.name
    elif db:
        stmt = select(EventType.name).where(EventType.id == event.event_type_id)
        event_type_name = db.execute(stmt).scalar_one_or_none() or ""
    
    category_name = ""
    if event.source_category_rel:
        category_name = event.source_category_rel.name
    elif db:
        stmt = select(SourceCategoryRef.name).where(SourceCategoryRef.id == event.source_category_id)
        category_name = db.execute(stmt).scalar_one_or_none() or ""
    
    severity_name = ""
    if event.severity_rel:
        severity_name = event.severity_rel.name
    elif db:
        stmt = select(SeverityLevel.name).where(SeverityLevel.id == event.severity_id)
        severity_name = db.execute(stmt).scalar_one_or_none() or ""
    
    event_type = event_type_name.lower()
    category = category_name.lower()
    severity = severity_name.lower()
    msg = (event.message or "").strip()
    base: str

    if event_type == "authentication":
        if any(k in msg.lower() for k in ("failed", "failure", "invalid", "denied")):
            base = "Ошибка входа: неверный пароль или учётные данные."
        else:
            base = "Событие аутентификации пользователя."

    elif event_type == "network":
        lower = msg.lower()
        if "timeout" in lower or "timed out" in lower:
            base = "Сбой сетевого соединения: истёк тайм-аут."
        elif "refused" in lower:
            base = "Сбой сетевого соединения: соединение отклонено удалённой стороной."
        elif "unreachable" in lower:
            base = "Сбой сетевого соединения: узел или сеть недоступны."
        else:
            base = "Сетевое событие, требующее внимания."

    elif event_type == "service":
        lower = msg.lower()
        if any(k in lower for k in ("crash", "terminated", "panic")):
            base = "Сбой системной или пользовательской службы."
        elif any(k in lower for k in ("restart", "exited", "failed to start")):
            base = "Перезапуск или некорректное завершение службы."
        else:
            base = "Событие, связанное с работой службы или демона."

    elif event_type == "process":
        base = "Событие, связанное с запуском или работой пользовательского процесса."

    else:
        if severity in ("critical", "high"):
            base = "Критическое системное событие."
        elif severity == "medium":
            base = "Системное предупреждение."
        else:
            base = "Информационное системное событие."

    if category == "service":
        base += " Источник: системная или прикладная служба."
    elif category == "user_process":
        base += " Источник: пользовательский процесс или приложение."
    elif category == "os":
        base += " Источник: операционная система."

    if msg:
        return f"{base} Детали: {msg}"

    return base


def format_incident_friendly_description(incident: Incident, db: Session = None) -> str:
    """
    Формирует дружественное описание инцидента.
    
    Args:
        incident: Инцидент
        db: Сессия БД (опционально, для получения названий справочников)
        
    Returns:
        Описание инцидента
    """
    # Получаем названия из связанных объектов или через БД
    incident_type_name = ""
    if incident.incident_type_rel:
        incident_type_name = incident.incident_type_rel.name
    elif db:
        stmt = select(IncidentType.name).where(IncidentType.id == incident.incident_type_id)
        incident_type_name = db.execute(stmt).scalar_one_or_none() or ""
    
    severity_name = ""
    if incident.severity_rel:
        severity_name = incident.severity_rel.name
    elif db:
        stmt = select(SeverityLevel.name).where(SeverityLevel.id == incident.severity_id)
        severity_name = db.execute(stmt).scalar_one_or_none() or ""
    
    itype = incident_type_name.lower()
    severity = severity_name.lower()
    details: dict = incident.details or {}
    count = details.get("count")

    if itype == "multiple_failed_logins":
        if count:
            return f"Множественные неудачные попытки аутентификации: обнаружено {count} событий за короткий промежуток времени."
        return "Множественные неудачные попытки аутентификации."

    if itype == "repeated_network_errors":
        if count:
            return f"Повторяющиеся сетевые ошибки: обнаружено {count} сетевых сбоев за анализируемый период."
        return "Повторяющиеся сетевые ошибки, указывающие на нестабильность сети."

    if itype == "service_crash_or_restart":
        if count:
            return f"Сбой или частые перезапуски службы: зарегистрировано {count} связанных событий."
        return "Сбой или частые перезапуски системной или пользовательской службы."

    if severity in ("critical", "high"):
        return "Критический инцидент информационной безопасности или стабильности системы."

    if severity == "medium":
        return "Инцидент средней важности, требующий анализа."

    return "Информационный инцидент, не требующий немедленного вмешательства."
