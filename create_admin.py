#!/usr/bin/env python3
"""Скрипт для создания пользователя admin."""

import sys
import os

# Добавляем backend в path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from siem_backend.data.db import SessionLocal, init_db
from siem_backend.data.user_repository import create_user

def main():
    # Инициализируем БД (создаёт таблицы если нет)
    init_db()
    
    # Создаём админа
    db = SessionLocal()
    try:
        user = create_user(db, username="admin", password="admin", role="admin")
        print(f"✅ Создан пользователь: {user.username}, роль: {user.role}")
        db.commit()
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == '__main__':
    main()
