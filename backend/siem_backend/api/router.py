from fastapi import APIRouter

from siem_backend.api.routes.analyze import router as analyze_router
from siem_backend.api.routes.auth import router as auth_router
from siem_backend.api.routes.collect import router as collect_router
from siem_backend.api.routes.events import router as events_router
from siem_backend.api.routes.health import router as health_router
from siem_backend.api.routes.incidents import router as incidents_router
from siem_backend.api.routes.notifications import router as notifications_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(auth_router)
api_router.include_router(collect_router, prefix="/collect", tags=["collect"])
api_router.include_router(analyze_router, prefix="/analyze", tags=["analyze"])
api_router.include_router(events_router, prefix="/events", tags=["events"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["incidents"])
api_router.include_router(notifications_router, prefix="/notifications", tags=["notifications"])
