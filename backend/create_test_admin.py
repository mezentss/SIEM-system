#!/usr/bin/env python3
"""Скрипт для создания тестового админа в backend БД."""

from siem_backend.data.db import SessionLocal
from siem_backend.data.user_repository import create_user

db = SessionLocal()
try:
    user = create_user(db, username="testadmin", password="test123", role="admin")
    print(f"✅ Создан: {user.username}, роль: {user.role}")
    db.commit()
except Exception as e:
    print(f"❌ Ошибка: {e}")
    db.rollback()
finally:
    db.close()
