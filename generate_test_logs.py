#!/usr/bin/env python3
"""
Генератор тестовых логов для SIEM-системы.
Создаёт реалистичные логи с ошибками приложений для тестирования.
"""

import datetime
import random
import os

# Приложения для генерации ошибок
APPS = [
    'zoom', 'Word', 'Excel', 'Safari', 'Chrome', 'Slack', 
    'Teams', 'Photoshop', 'Finder', 'Mail', 'Calendar',
    'nginx', 'mysql', 'redis', 'docker'
]

# Типы ошибок
ERRORS = [
    'Application crashed: out of memory',
    'Failed to initialize component',
    'Application exited unexpectedly with code 1',
    'Document save failed: disk full',
    'Application terminated unexpectedly',
    'Connection failed: timeout',
    'Worker process crashed with signal 11',
    'Segmentation fault (core dumped)',
    'Fatal error: unable to allocate memory',
    'Process killed due to high CPU usage',
    'Failed to connect to server: connection refused',
    'Database connection lost',
    'File not found: config.json',
    'Permission denied: /var/log/app.log',
    'SSL handshake failed',
]

# Серьёзности
SEVERITIES = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']

# Соотношение серьёзностей (больше ошибок, меньше инфо)
SEVERITY_WEIGHTS = [0.1, 0.2, 0.5, 0.2]


def generate_log_entry(ts):
    """Генерирует одну запись лога."""
    app = random.choice(APPS)
    error = random.choice(ERRORS)
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
    pid = random.randint(1000, 9999)
    
    # Формат: 2026-02-19 10:00:00,000 ERROR zoom[1234]: message
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')},{random.randint(0, 999):03d} {severity} {app}[{pid}]: {error}\n"


def generate_systemd_entry(ts, app):
    """Генерирует запись лога systemd о сбое сервиса."""
    templates = [
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')},000 INFO systemd[1]: {app}.service: Main process exited, status=1/FAILURE\n",
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')},000 INFO systemd[1]: {app}.service: Failed with result 'exit-code'\n",
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')},000 INFO systemd[1]: {app}.service: Service hold-off time over, scheduling restart\n",
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')},000 INFO systemd[1]: {app}.service: Restarting...\n",
    ]
    return random.choice(templates)


def main():
    """Основная функция."""
    # Определяем путь к файлу логов - используем backend/logs/system.log
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, 'backend', 'logs', 'system.log')
    
    # Если backend/logs не существует, пробуем logs/
    if not os.path.exists(os.path.dirname(log_file)):
        log_file = os.path.join(script_dir, 'logs', 'system.log')
        # Создаём директорию если не существует
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Генерируем записи
    entries = []
    now = datetime.datetime.now()
    
    # 20 случайных ошибок за последний час
    for _ in range(20):
        ts = now - datetime.timedelta(minutes=random.randint(0, 60))
        entries.append((ts, generate_log_entry(ts)))
    
    # 5 сбоев systemd для разных приложений
    for app in random.sample(APPS, 5):
        ts = now - datetime.timedelta(minutes=random.randint(0, 60))
        entries.append((ts, generate_systemd_entry(ts, app)))
    
    # Сортируем по времени
    entries.sort(key=lambda x: x[0])
    
    # Записываем в файл
    with open(log_file, 'a') as f:
        for _, entry in entries:
            f.write(entry)
    
    print(f"✅ Сгенерировано {len(entries)} тестовых записей")
    print(f"📁 Файл: {log_file}")
    print(f"\n📊 Приложения: {', '.join(set(random.choices(APPS, k=8)))}")
    print(f"\nЗапустите 'Собрать события из файла' в SIEM для импорта логов")


if __name__ == '__main__':
    main()
