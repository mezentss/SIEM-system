from __future__ import annotations

from collections.abc import Iterator
from typing import List

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from siem_backend.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, class_=Session, autoflush=False, autocommit=False)


def _check_table_schema(table_name: str, required_columns: List[str]) -> bool:
    """Проверяет, что таблица имеет все необходимые колонки."""
    inspector = inspect(engine)
    if not inspector.has_table(table_name):
        return False

    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return all(col in columns for col in required_columns)


def init_db() -> None:
    from siem_backend.data import models  # noqa: F401

    # Требуемые колонки для каждой таблицы
    required_columns = {
        "events": ["id", "ts", "source_os", "source_category", "event_type", "severity", "message", "raw_data"],
        "incidents": ["id", "detected_at", "incident_type", "severity", "description", "event_id", "details"],
        "notifications": [
            "id", "created_at", "notification_type", "severity", "title", "message",
            "incident_id", "event_id", "channel", "status", "details"
        ],
    }

    # Проверяем схему всех таблиц
    needs_recreate = False
    for table_name, columns in required_columns.items():
        if not _check_table_schema(table_name, columns):
            needs_recreate = True
            break

    # Если схема не соответствует - пересоздаем все таблицы
    if needs_recreate:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA foreign_keys=OFF"))
            conn.commit()

        Base.metadata.drop_all(bind=engine)

        with engine.connect() as conn:
            conn.execute(text("PRAGMA foreign_keys=ON"))
            conn.commit()

    # Создаем все таблицы с актуальной схемой
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
