from __future__ import annotations

from typing import Optional

import bcrypt
from sqlalchemy.orm import Session

from siem_backend.data.models_user import User


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        # Fallback: ensure hashed is bytes
        return bcrypt.checkpw(password.encode('utf-8'), hashed)


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def create_user(db: Session, username: str, password: str, role: str = "operator") -> User:
    hashed = hash_password(password)
    db_user = User(username=username, hashed_password=hashed, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
