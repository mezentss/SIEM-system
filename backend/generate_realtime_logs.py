#!/usr/bin/env python3
'''
Генератор тестовых логов в реальном времени.
Добавляет новые ошибки в файл логов каждые 5 секунд.

Запуск:
    python3 generate_realtime_logs.py

'''

import datetime
import random
import time
import os

LOG_FILE = "./logs/system.log"

ERROR_TEMPLATES = [
    ("ERROR", "nginx[{pid}]: Connection timeout to {host}:{port}"),
    ("ERROR", "sshd[{pid}]: Failed login attempt for user {user}"),
    ("ERROR", "nginx[{pid}]: Connection refused to {host}:{port}"),
    ("CRITICAL", "zoom[{pid}]: Application crashed: out of memory"),
    ("ERROR", "systemd[1]: {service}.service: Main process exited, status=1/FAILURE"),
    ("ERROR", "nginx[{pid}]: Network unreachable to {host}:{port}"),
    ("ERROR", "sshd[{pid}]: Failed password for user {user}"),
    ("ERROR", "nginx[{pid}]: Socket error: connection timed out"),
    ("CRITICAL", "launchd[0]: {service} terminated unexpectedly"),
    ("ERROR", "nginx[{pid}]: DNS lookup failed for {host}"),
]

HOSTS = ["10.0.0.5", "192.168.1.100", "backend-server", "database-server", "cache-server"]
USERS = ["admin", "root", "user1", "operator", "testuser"]
SERVICES = ["nginx", "mysql", "redis", "postgresql", "docker", "elasticsearch"]

def generate_log_line():
    level, template = random.choice(ERROR_TEMPLATES)
    pid = random.randint(1000, 9999)
    host = random.choice(HOSTS)
    port = random.choice([80, 443, 5432, 6379, 8080, 9200])
    user = random.choice(USERS)
    service = random.choice(SERVICES)
    
    message = template.format(pid=pid, host=host, port=port, user=user, service=service)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S,000")
    
    return f"{ts} {level} {message}"

def main():
    print("Генератор тестовых логов запущен")
    print(f"Файл логов: {os.path.abspath(LOG_FILE)}")
    print("Новые ошибки добавляются каждые 5 секунд")
    print("Нажмите Ctrl+C для остановки")
    print()
    
    count = 0
    while True:
        line = generate_log_line()
        
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
        
        count += 1
        print(f"[{count}] {line}")
        
        time.sleep(5)

if __name__ == "__main__":
    main()
