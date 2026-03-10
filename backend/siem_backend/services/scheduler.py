import threading
import time
import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from siem_backend.core.config import settings
from siem_backend.services.incident_service import IncidentService

logger = logging.getLogger(__name__)

ANALYSIS_INTERVAL_MINUTES = int(os.getenv("ANALYSIS_INTERVAL_MINUTES", "5"))


def run_scheduled_analysis():
    try:
        engine = create_engine(settings.database_url, future=True)
        SessionLocal = sessionmaker(bind=engine, class_=Session, autoflush=False, autocommit=False)
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
    logger.info(f"Scheduled analysis started (interval: {ANALYSIS_INTERVAL_MINUTES} minutes)")
    while True:
        time.sleep(ANALYSIS_INTERVAL_MINUTES * 60)
        run_scheduled_analysis()


def start_scheduler():
    scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    scheduler_thread.start()
    logger.info("Scheduler thread started")


start_scheduler()
