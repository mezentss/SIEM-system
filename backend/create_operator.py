#!/usr/bin/env python3
"""Скрипт для создания тестового оператора в backend БД."""

from siem_backend.data.db import SessionLocal
from siem_backend.data.user_repository import create_user

db = SessionLocal()
try:
    user = create_user(db, username="operator", password="operator", role="operator")
    print(f"✅ Создан: {user.username}, роль: {user.role}")
    db.commit()
except Exception as e:
    print(f"❌ Ошибка: {e}")
    db.rollback()
finally:
    db.close()
