from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from siem_backend.data.db import get_db
from siem_backend.data.user_repository import get_user_by_username, verify_password

security = HTTPBasic()


def get_current_user(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
    db: Session = Depends(get_db),
):
    print(f"[DEBUG] Auth attempt: username={credentials.username}, password={credentials.password}")
    user = get_user_by_username(db, credentials.username)
    if not user:
        print(f"[DEBUG] User not found: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not verify_password(credentials.password, user.hashed_password):
        print(f"[DEBUG] Password mismatch for user: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    print(f"[DEBUG] Auth success for: {credentials.username}")
    return user


def require_admin(current_user = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user
