from __future__ import annotations

from typing import Any

from siem_backend.data.models import Event, Incident


def format_event_description(event: Event) -> str:
    """
    Формирует человеко-читаемое описание события.

    Использует комбинацию event_type, source_category, severity и исходного сообщения.
    Бизнес-логика анализа и структура БД не изменяются.
    """
    event_type = (event.event_type or "").lower()
    category = (event.source_category or "").lower()
    severity = (event.severity or "").lower()
    msg = (event.message or "").strip()
    base: str

    # Аутентификация
    if event_type == "authentication":
        if any(k in msg.lower() for k in ("failed", "failure", "invalid", "denied")):
            base = "Ошибка входа: неверный пароль или учётные данные."
        else:
            base = "Событие аутентификации пользователя."

    # Сетевые события
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

    # Службы и процессы
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

    # По умолчанию — системные события
    else:
        if severity in ("critical", "high"):
            base = "Критическое системное событие."
        elif severity == "medium":
            base = "Системное предупреждение."
        else:
            base = "Информационное системное событие."

    # Добавляем контекст по источнику
    if category == "service":
        base += " Источник: системная или прикладная служба."
    elif category == "user_process":
        base += " Источник: пользовательский процесс или приложение."
    elif category == "os":
        base += " Источник: операционная система."

    # Если есть короткое сообщение, добавляем его в конце
    if msg:
        return f"{base} Детали: {msg}"

    return base


def format_incident_friendly_description(incident: Incident) -> str:
    """
    Формирует человеко-читаемое описание инцидента на основе incident_type и details.

    Поле Incident.description в БД не трогаем — используем это как "friendly" текст для фронтенда.
    """
    itype = (incident.incident_type or "").lower()
    severity = (incident.severity or "").lower()
    details: dict[str, Any] = incident.details or {}
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

    # Общее человеко-читаемое описание по умолчанию
    if severity in ("critical", "high"):
        return "Критический инцидент информационной безопасности или стабильности системы."

    if severity == "medium":
        return "Инцидент средней важности, требующий анализа."

    return "Информационный инцидент, не требующий немедленного вмешательства."

