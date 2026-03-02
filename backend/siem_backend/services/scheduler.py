"""
Фоновый планировщик для периодического запуска анализа.
Запускает анализ каждые 10 минут независимо от действий пользователей.
"""

import threading
import time
import logging

from sqlalchemy.orm import Session

from siem_backend.data.db import SessionLocal
from siem_backend.services.incident_service import IncidentService

logger = logging.getLogger(__name__)

ANALYSIS_INTERVAL_MINUTES = 10  # Интервал запуска анализа


def run_scheduled_analysis():
    """Запускает анализ инцидентов."""
    try:
        db: Session = SessionLocal()
        try:
            service = IncidentService()
            incidents_found = service.run_analysis(db, since_minutes=60)
            if incidents_found > 0:
                logger.info(f"Scheduled analysis found {incidents_found} incidents")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Scheduled analysis failed: {e}")


def _scheduler_loop():
    """Фоновый цикл планировщика."""
    logger.info(f"Scheduled analysis started (interval: {ANALYSIS_INTERVAL_MINUTES} minutes)")
    while True:
        time.sleep(ANALYSIS_INTERVAL_MINUTES * 60)
        run_scheduled_analysis()


def start_scheduler():
    """Запускает планировщик в фоновом потоке."""
    scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    scheduler_thread.start()
    logger.info("Scheduler thread started")


# Запускаем планировщик при импорте модуля (при старте приложения)
start_scheduler()
