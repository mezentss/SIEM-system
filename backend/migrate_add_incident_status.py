#!/usr/bin/env python3
"""
Миграция: Добавление полей статуса в таблицу incidents.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from siem_backend.core.config import settings

engine = create_engine(settings.database_url, future=True)
conn = engine.connect()

try:
    # Добавляем поле status
    conn.execute(text("""
        ALTER TABLE incidents ADD COLUMN status VARCHAR(16) DEFAULT 'active'
    """))
    print("✓ Добавлено поле status")
except Exception as e:
    if "duplicate column" not in str(e).lower():
        print(f"✗ Ошибка добавления status: {e}")
    else:
        print("✓ Поле status уже существует")

try:
    # Добавляем поле resolved_at
    conn.execute(text("""
        ALTER TABLE incidents ADD COLUMN resolved_at DATETIME
    """))
    print("✓ Добавлено поле resolved_at")
except Exception as e:
    if "duplicate column" not in str(e).lower():
        print(f"✗ Ошибка добавления resolved_at: {e}")
    else:
        print("✓ Поле resolved_at уже существует")

try:
    # Добавляем поле resolved_by
    conn.execute(text("""
        ALTER TABLE incidents ADD COLUMN resolved_by VARCHAR(64)
    """))
    print("✓ Добавлено поле resolved_by")
except Exception as e:
    if "duplicate column" not in str(e).lower():
        print(f"✗ Ошибка добавления resolved_by: {e}")
    else:
        print("✓ Поле resolved_by уже существует")

try:
    # Добавляем поле resolution_notes
    conn.execute(text("""
        ALTER TABLE incidents ADD COLUMN resolution_notes TEXT
    """))
    print("✓ Добавлено поле resolution_notes")
except Exception as e:
    if "duplicate column" not in str(e).lower():
        print(f"✗ Ошибка добавления resolution_notes: {e}")
    else:
        print("✓ Поле resolution_notes уже существует")

conn.commit()
conn.close()

print("\n=== Миграция завершена ===")
