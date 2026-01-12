from fastapi import FastAPI

from siem_backend.api.router import api_router
from siem_backend.core.config import settings
from siem_backend.core.logging import configure_logging
from siem_backend.data.db import init_db


def create_app() -> FastAPI:
    configure_logging(settings.log_level)
    init_db()

    app = FastAPI(title=settings.app_name)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
