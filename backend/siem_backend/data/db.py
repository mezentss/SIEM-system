from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from siem_backend.core.config import settings
from siem_backend.data.schemas import Base


def _create_engine() -> any:
    """
    Создаёт движок SQLAlchemy с настройками для выбранной СУБД.
    
    PostgreSQL (для предприятия):
    - Пул соединений с переподключением
    - Многопользовательский доступ
    - Масштабируемость
    
    SQLite (для локальной разработки):
    - FOREIGN KEY включены
    - WAL режим для производительности
    """
    if settings.is_postgresql:
        # PostgreSQL: пул соединений для многопользовательского доступа
        engine = create_engine(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout,
            pool_recycle=settings.db_pool_recycle,
            echo=False,
        )
    else:
        # SQLite: локальный режим для разработки
        engine = create_engine(
            settings.database_url,
            future=True,
            connect_args={"check_same_thread": False},
        )
        
        # Включаем поддержку FOREIGN KEY
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        
        # Включаем WAL режим
        @event.listens_for(engine, "connect")
        def set_sqlite_wal(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
    
    return engine


# Создаём движок
engine = _create_engine()

# Создаём фабрику сессий
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    autocommit=False
)


def init_db() -> None:
    """
    Инициализирует базу данных:
    - Создаёт все таблицы
    - Инициализирует справочные данные
    """
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        from siem_backend.data.initial_data import init_reference_data
        init_reference_data(db)
    finally:
        db.close()


def get_db() -> Iterator[Session]:
    """
    Получает сессию БД для каждого запроса.
    Используется в FastAPI зависимостях.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
