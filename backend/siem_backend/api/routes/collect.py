from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from siem_backend.api.auth import require_admin
from siem_backend.services.collectors.file import FileLogCollector
from siem_backend.services.collectors.macos import MacOSLogCollector, normalized_event_to_dict
from siem_backend.services.collectors.mock import MockLogCollector
from siem_backend.data.db import get_db
from siem_backend.services.event_service import EventService
from siem_backend.services.system_log_exporter import SystemLogExporter

router = APIRouter()


@router.post("/test")
def collect_test(
    last: str = Query(default="2m"),
    max_entries: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _ = Depends(require_admin),
) -> dict:
    collector = MacOSLogCollector(last=last, max_entries=max_entries)
    events = collector.collect()
    saved_count = EventService().save_normalized_events(db, events)
    return {
        "collected_count": len(events),
        "saved_count": saved_count,
        "events": [normalized_event_to_dict(e) for e in events],
    }


@router.post("/file")
def collect_file(
    file_path: str = Query(default="./logs/system.log"),
    max_lines: int = Query(default=100, ge=1, le=5000),
    db: Session = Depends(get_db),
    _ = Depends(require_admin),
) -> dict:
    collector = FileLogCollector(file_path=file_path, max_lines=max_lines)
    events = collector.collect()
    saved_count = EventService().save_normalized_events(db, events)
    return {
        "collected_count": len(events),
        "saved_count": saved_count,
    }


@router.post("/mock")
def collect_mock(
    event_count: int = Query(default=18, ge=10, le=20),
    db: Session = Depends(get_db),
    _ = Depends(require_admin),
) -> dict:
    collector = MockLogCollector(event_count=event_count)
    events = collector.collect()
    saved_count = EventService().save_normalized_events(db, events)
    return {
        "collected_count": len(events),
        "saved_count": saved_count,
        "events": [normalized_event_to_dict(e) for e in events],
    }


@router.post("/system")
def collect_system(
    last_minutes: int = Query(default=5, ge=1, le=60),
    max_lines: int = Query(default=200, ge=1, le=5000),
    db: Session = Depends(get_db),
    _ = Depends(require_admin),
) -> dict:
    """
    Собирает реальные логи macOS и сохраняет события в БД.

    Процесс:
    1. Экспортирует системные логи macOS в backend/logs/system.log
    2. Читает файл через FileLogCollector
    3. Сохраняет события в БД

    Args:
        last_minutes: Количество минут для получения логов (1-60)
        max_lines: Максимальное количество строк для обработки (1-5000)

    Returns:
        Словарь с результатами экспорта и сбора
    """
    # Шаг 1: Экспорт логов ОС в файл
    exporter = SystemLogExporter(output_file="./logs/system.log")
    exported = exporter.export_logs(last_minutes=last_minutes)

    if not exported:
        return {
            "exported": False,
            "collected_count": 0,
            "saved_count": 0,
            "error": "Failed to export system logs",
        }

    # Шаг 2: Чтение файла через FileLogCollector
    collector = FileLogCollector(file_path="./logs/system.log", max_lines=max_lines)
    events = collector.collect()

    # Шаг 3: Сохранение событий в БД
    saved_count = EventService().save_normalized_events(db, events)

    return {
        "exported": True,
        "collected_count": len(events),
        "saved_count": saved_count,
    }
