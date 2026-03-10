from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from siem_backend.core.config import settings
from siem_backend.data.schemas import Base


def init_db() -> None:
    engine = create_engine(settings.database_url, future=True)
    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(bind=engine, class_=Session, autoflush=False, autocommit=False)
    db = SessionLocal()
    try:
        from siem_backend.data.initial_data import init_reference_data
        init_reference_data(db)
    finally:
        db.close()


def get_db() -> Iterator[Session]:
    engine = create_engine(settings.database_url, future=True)
    SessionLocal = sessionmaker(bind=engine, class_=Session, autoflush=False, autocommit=False)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
