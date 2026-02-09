from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from siem_backend.api.auth import get_current_user
from siem_backend.data.models_user import User

router = APIRouter(tags=["auth"])


@router.get("/auth/me")
def read_current_user(current_user: Annotated[User, Depends(get_current_user)]) -> dict:
    return {"username": current_user.username, "role": current_user.role}
