"""
Скрипт миграции данных из SQLite в PostgreSQL.

Использование:
    python -m siem_backend.scripts.migrate_to_postgres \
        --sqlite-db ./siem.db \
        --postgres-url postgresql+psycopg2://user:password@host:5432/siem_db

Или через переменные окружения:
    SIEM_SQLITE_DB=./siem.db \
    SIEM_DATABASE_URL=postgresql+psycopg2://user:password@host:5432/siem_db \
    python -m siem_backend.scripts.migrate_to_postgres
"""

import argparse
import sys
from pathlib import Path

# Добавляем корень проекта в path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy import create_engine, MetaData, Table, select, insert
from sqlalchemy.orm import Session
from tqdm import tqdm

from siem_backend.core.config import settings
from siem_backend.data.models import Base
from siem_backend.data.initial_data import init_reference_data


def get_sqlite_engine(sqlite_path: str):
    """Создаёт движок для SQLite."""
    return create_engine(f"sqlite:///{sqlite_path}")


def get_postgres_engine(pg_url: str):
    """Создаёт движок для PostgreSQL."""
    return create_engine(
        pg_url,
        pool_size=5,
        max_overflow=2,
        pool_timeout=10,
    )


def migrate_table(sqlite_conn, pg_conn, table_name: str, batch_size: int = 1000):
    """
    Мигрирует данные из одной таблицы SQLite в PostgreSQL.
    
    Args:
        sqlite_conn: Соединение с SQLite
        pg_conn: Соединение с PostgreSQL
        table_name: Имя таблицы
        batch_size: Размер пакета для вставки
    """
    print(f"\nМиграция таблицы: {table_name}")
    
    # Получаем метаданные из SQLite
    sqlite_meta = MetaData()
    sqlite_meta.reflect(bind=sqlite_conn)
    
    if table_name not in sqlite_meta.tables:
        print(f"  Таблица {table_name} не найдена в SQLite, пропускаем")
        return 0
    
    sqlite_table = sqlite_meta.tables[table_name]
    
    # Получаем все данные из SQLite
    stmt = select(sqlite_table)
    rows = sqlite_conn.execute(stmt).fetchall()
    
    if not rows:
        print(f"  Таблица {table_name} пуста")
        return 0
    
    print(f"  Найдено записей: {len(rows)}")
    
    # Вставляем данные в PostgreSQL
    pg_meta = MetaData()
    pg_meta.reflect(bind=pg_conn)
    
    if table_name not in pg_meta.tables:
        print(f"  Таблица {table_name} не найдена в PostgreSQL, создаём")
        return 0
    
    pg_table = pg_meta.tables[table_name]
    
    # Вставляем пакетами
    total_inserted = 0
    for i in tqdm(range(0, len(rows), batch_size), desc=f"  {table_name}"):
        batch = rows[i:i + batch_size]
        
        # Преобразуем строки в словари
        batch_dicts = []
        for row in batch:
            row_dict = dict(row._mapping)
            batch_dicts.append(row_dict)
        
        # Вставляем в PostgreSQL
        pg_conn.execute(insert(pg_table), batch_dicts)
        total_inserted += len(batch)
    
    pg_conn.commit()
    print(f"  Вставлено записей: {total_inserted}")
    return total_inserted


def run_migration(sqlite_path: str, pg_url: str):
    """
    Запускает полную миграцию из SQLite в PostgreSQL.
    
    Args:
        sqlite_path: Путь к файлу SQLite
        pg_url: URL подключения к PostgreSQL
    """
    print("=" * 60)
    print("Миграция данных из SQLite в PostgreSQL")
    print("=" * 60)
    
    # Создаём движки
    sqlite_engine = get_sqlite_engine(sqlite_path)
    pg_engine = get_postgres_engine(pg_url)
    
    # Создаём все таблицы в PostgreSQL
    print("\nСоздание таблиц в PostgreSQL...")
    Base.metadata.create_all(bind=pg_engine)
    
    # Инициализируем справочные данные
    print("\nИнициализация справочных данных...")
    with Session(pg_engine) as pg_session:
        init_reference_data(pg_session)
        print("Справочники заполнены.")
    
    # Мигрируем данные
    print("\nМиграция данных...")
    tables_to_migrate = [
        "source_os",
        "source_categories",
        "event_types",
        "severity_levels",
        "incident_types",
        "notification_types",
        "events",
        "incidents",
        "notifications",
        "users",
        "analysis_rules",
        "log_sources",
        "system_runs",
        "rule_triggers",
    ]
    
    total_migrated = 0
    with sqlite_engine.connect() as sqlite_conn, pg_engine.connect() as pg_conn:
        for table_name in tables_to_migrate:
            try:
                count = migrate_table(sqlite_conn, pg_conn, table_name)
                total_migrated += count
            except Exception as e:
                print(f"  Ошибка миграции {table_name}: {e}")
                pg_conn.rollback()
    
    print("\n" + "=" * 60)
    print(f"Миграция завершена! Всего перенесено записей: {total_migrated}")
    print("=" * 60)
    print("\nСледующие шаги:")
    print("1. Обновите .env файл: SIEM_DATABASE_URL=postgresql+psycopg2://...")
    print("2. Перезапустите backend: uvicorn siem_backend.main:app --reload")
    print("3. Проверьте работу: curl http://localhost:8000/api/health")


def main():
    parser = argparse.ArgumentParser(description="Миграция SQLite → PostgreSQL")
    parser.add_argument(
        "--sqlite-db",
        default="./siem.db",
        help="Путь к файлу SQLite (по умолчанию: ./siem.db)"
    )
    parser.add_argument(
        "--postgres-url",
        default=None,
        help="URL подключения к PostgreSQL"
    )
    
    args = parser.parse_args()
    
    # Если URL не указан, берём из настроек
    pg_url = args.postgres_url or settings.database_url
    
    if not pg_url or not pg_url.startswith("postgresql"):
        print("Ошибка: укажите URL подключения к PostgreSQL")
        print("  --postgres-url postgresql+psycopg2://user:pass@host:5432/db")
        sys.exit(1)
    
    run_migration(args.sqlite_db, pg_url)


if __name__ == "__main__":
    main()
