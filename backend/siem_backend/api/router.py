from fastapi import APIRouter

from siem_backend.api.routes.collect import router as collect_router
from siem_backend.api.routes.events import router as events_router
from siem_backend.api.routes.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(collect_router, prefix="/collect", tags=["collect"])
api_router.include_router(events_router, prefix="/events", tags=["events"])
