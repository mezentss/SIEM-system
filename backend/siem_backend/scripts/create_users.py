#!/usr/bin/env python3
"""
Создание пользователей для SIEM.
Запускать из корня backend: python -m siem_backend.scripts.create_users
"""

from __future__ import annotations

import sys

from siem_backend.data.db import init_db, SessionLocal
from siem_backend.data.user_repository import create_user, get_user_by_username


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        # Создаем администратора
        if not get_user_by_username(db, "admin"):
            create_user(db, "admin", "admin123", role="admin")
            print("✅ Создан пользователь: admin (пароль: admin123, роль: admin)")
        else:
            print("ℹ️  Пользователь 'admin' уже существует")

        # Создаем оператора
        if not get_user_by_username(db, "operator"):
            create_user(db, "operator", "operator123", role="operator")
            print("✅ Создан пользователь: operator (пароль: operator123, роль: operator)")
        else:
            print("ℹ️  Пользователь 'operator' уже существует")
    finally:
        db.close()


if __name__ == "__main__":
    main()
