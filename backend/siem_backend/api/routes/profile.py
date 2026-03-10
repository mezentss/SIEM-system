from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from siem_backend.api.auth import get_current_user
from siem_backend.data.db import get_db
from siem_backend.data.models_user import User
from siem_backend.data.user_repository import create_user, verify_password


class UserProfile(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


class UserProfileOut(BaseModel):
    username: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


class UserRegister(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


router = APIRouter()


@router.get("/me", response_model=UserProfileOut)
def get_profile(
    current_user: User = Depends(get_current_user),
) -> UserProfileOut:
    return UserProfileOut(
        username=current_user.username,
        role=current_user.role,
        full_name=current_user.full_name,
        email=current_user.email,
        phone=current_user.phone,
    )


@router.put("/me", response_model=UserProfileOut)
def update_profile(
    profile: UserProfile,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserProfileOut:
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if profile.full_name is not None:
        user.full_name = profile.full_name
    if profile.email is not None:
        user.email = profile.email
    if profile.phone is not None:
        user.phone = profile.phone
    
    db.commit()
    db.refresh(user)
    
    return UserProfileOut(
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        email=user.email,
        phone=user.phone,
    )


@router.post("/register", response_model=UserProfileOut)
def register_user(
    user_data: UserRegister,
    db: Session = Depends(get_db),
) -> UserProfileOut:
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if len(user_data.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    
    user = create_user(
        db=db,
        username=user_data.username,
        password=user_data.password,
        role="operator"
    )
    
    if user_data.full_name:
        user.full_name = user_data.full_name
    if user_data.email:
        user.email = user_data.email
    if user_data.phone:
        user.phone = user_data.phone
    
    db.commit()
    db.refresh(user)
    
    return UserProfileOut(
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        email=user.email,
        phone=user.phone,
    )
