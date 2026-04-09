import threading
import time
import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from siem_backend.core.config import settings
from siem_backend.data.db import engine as app_engine
from siem_backend.services.incident_service import IncidentService

logger = logging.getLogger(__name__)

ANALYSIS_INTERVAL_MINUTES = int(os.getenv("ANALYSIS_INTERVAL_MINUTES", "5"))


def run_scheduled_analysis():
    """
    Запускает плановый анализ инцидентов.
    
    Использует тот же пул соединений, что и основное приложение.
    """
    try:
        # Используем движок из основного приложения
        SessionLocal = sessionmaker(
            bind=app_engine,
            class_=Session,
            autoflush=False,
            autocommit=False
        )
        db: Session = SessionLocal()
        try:
            service = IncidentService()
            incidents_found = service.run_analysis(db, since_minutes=60)
            if incidents_found > 0:
                logger.info(f"Scheduled analysis found {incidents_found} incidents")

            # Автоматическое закрытие старых инцидентов
            resolved = service.auto_resolve_inactive_incidents(db, minutes=60)
            if resolved > 0:
                logger.info(f"Auto-resolved {resolved} inactive incidents")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Scheduled analysis failed: {e}")


def _scheduler_loop():
    """Основной цикл планировщика."""
    logger.info(f"Scheduled analysis started (interval: {ANALYSIS_INTERVAL_MINUTES} minutes)")
    while True:
        time.sleep(ANALYSIS_INTERVAL_MINUTES * 60)
        run_scheduled_analysis()


def start_scheduler():
    """Запускает планировщик в фоновом потоке."""
    scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    scheduler_thread.start()
    logger.info("Scheduler thread started")


start_scheduler()
