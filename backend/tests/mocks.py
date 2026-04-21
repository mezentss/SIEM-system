"""
Моки для тестирования SIEM-системы.

Содержит фабрики тестовых данных для имитации работы системы:
- События безопасности (разных типов и уровней серьёзности)
- Инциденты
- Пользователи
- Уведомления

Использование:
    from tests.mocks import EventFactory, IncidentFactory
    
    # Создать тестовое событие
    event = EventFactory.create_auth_failed()
    
    # Создать тестовый инцидент
    incident = IncidentFactory.create_critical_incident()
"""

import datetime as dt
from typing import Any, Dict, List, Optional


# =============================================================================
# Фабрика событий
# =============================================================================

class EventFactory:
    """Фабрика для создания тестовых событий безопасности."""
    
    @staticmethod
    def create_auth_failed(
        ts: Optional[dt.datetime] = None,
        message: str = "Failed login attempt for user admin",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие неудачной попытки входа."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "auth",
            "event_type": "authentication",
            "severity": "high",
            "message": message,
            "raw_data": raw_data or {"process": "sshd", "user": "admin"},
        }
    
    @staticmethod
    def create_auth_success(
        ts: Optional[dt.datetime] = None,
        message: str = "Successful login for user admin",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие успешной аутентификации."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "auth",
            "event_type": "authentication",
            "severity": "low",
            "message": message,
            "raw_data": raw_data or {"process": "sshd", "user": "admin"},
        }
    
    @staticmethod
    def create_network_error(
        ts: Optional[dt.datetime] = None,
        message: str = "Connection timeout to 10.0.0.5:80",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие сетевой ошибки."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "network",
            "event_type": "network",
            "severity": "medium",
            "message": message,
            "raw_data": raw_data or {"process": "nginx", "target": "10.0.0.5:80"},
        }
    
    @staticmethod
    def create_network_critical(
        ts: Optional[dt.datetime] = None,
        message: str = "Network unreachable: connection refused",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Критическое сетевое событие."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "network",
            "event_type": "network",
            "severity": "critical",
            "message": message,
            "raw_data": raw_data or {"process": "nginx", "error": "connection_refused"},
        }
    
    @staticmethod
    def create_service_crash(
        ts: Optional[dt.datetime] = None,
        message: str = "nginx.service: Main process exited, status=1/FAILURE",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие сбоя службы."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "service",
            "event_type": "service",
            "severity": "high",
            "message": message,
            "raw_data": raw_data or {"process": "nginx", "service": "nginx.service"},
        }
    
    @staticmethod
    def create_service_restart(
        ts: Optional[dt.datetime] = None,
        message: str = "launchd: service terminated unexpectedly, restarting",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие перезапуска службы."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "service",
            "event_type": "service",
            "severity": "medium",
            "message": message,
            "raw_data": raw_data or {"process": "launchd", "service": "com.apple.service"},
        }
    
    @staticmethod
    def create_process_error(
        ts: Optional[dt.datetime] = None,
        message: str = "Application crashed: out of memory",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Событие ошибки приложения."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "user_process",
            "event_type": "process",
            "severity": "high",
            "message": message,
            "raw_data": raw_data or {"process": "zoom", "application": "zoom"},
        }
    
    @staticmethod
    def create_system_info(
        ts: Optional[dt.datetime] = None,
        message: str = "System startup completed successfully",
        raw_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Информационное системное событие."""
        return {
            "ts": ts or dt.datetime.utcnow(),
            "source_os": "macos",
            "source_category": "os",
            "event_type": "system",
            "severity": "low",
            "message": message,
            "raw_data": raw_data or {"process": "kernel"},
        }
    
    @staticmethod
    def create_batch_auth_failed(
        count: int = 10,
        interval_seconds: int = 30
    ) -> List[Dict[str, Any]]:
        """Пакет событий неудачных попыток входа (для тестирования правил)."""
        events = []
        base_time = dt.datetime.utcnow() - dt.timedelta(minutes=5)
        
        for i in range(count):
            ts = base_time + dt.timedelta(seconds=i * interval_seconds)
            events.append(EventFactory.create_auth_failed(
                ts=ts,
                message=f"Failed login attempt for user admin from 192.168.1.{100+i}"
            ))
        
        return events
    
    @staticmethod
    def create_batch_network_errors(
        count: int = 15,
        interval_seconds: int = 20
    ) -> List[Dict[str, Any]]:
        """Пакет событий сетевых ошибок (для тестирования правил)."""
        events = []
        base_time = dt.datetime.utcnow() - dt.timedelta(minutes=10)
        
        for i in range(count):
            ts = base_time + dt.timedelta(seconds=i * interval_seconds)
            events.append(EventFactory.create_network_error(
                ts=ts,
                message=f"Connection timeout to backend-server-{i}:8080"
            ))
        
        return events
    
    @staticmethod
    def create_batch_service_crashes(
        count: int = 5,
        interval_seconds: int = 60
    ) -> List[Dict[str, Any]]:
        """Пакет событий сбоев служб (для тестирования правил)."""
        events = []
        base_time = dt.datetime.utcnow() - dt.timedelta(minutes=30)
        
        for i in range(count):
            ts = base_time + dt.timedelta(seconds=i * interval_seconds)
            events.append(EventFactory.create_service_crash(
                ts=ts,
                message=f"nginx.service: Main process exited, status=1/FAILURE (attempt {i+1})"
            ))
        
        return events


# =============================================================================
# Фабрика инцидентов
# =============================================================================

class IncidentFactory:
    """Фабрика для создания тестовых инцидентов."""
    
    @staticmethod
    def create_multiple_failed_logins(
        detected_at: Optional[dt.datetime] = None,
        count: int = 10,
        severity: str = "critical"
    ) -> Dict[str, Any]:
        """Инцидент множественных неудачных попыток входа."""
        return {
            "detected_at": detected_at or dt.datetime.utcnow(),
            "incident_type": "multiple_failed_logins",
            "severity": severity,
            "description": f"Multiple failed login attempts detected: {count} events within last 5 minutes.",
            "event_id": None,
            "details": {
                "count": count,
                "threshold": 5,
                "window_minutes": 5,
                "keywords": ["failed password", "failed login attempt", "authentication failure"],
            },
            "status": "active",
            "resolved_at": None,
            "resolved_by": None,
            "resolution_notes": None,
        }
    
    @staticmethod
    def create_network_errors(
        detected_at: Optional[dt.datetime] = None,
        count: int = 15,
        severity: str = "medium"
    ) -> Dict[str, Any]:
        """Инцидент повторяющихся сетевых ошибок."""
        return {
            "detected_at": detected_at or dt.datetime.utcnow(),
            "incident_type": "repeated_network_errors",
            "severity": severity,
            "description": f"Repeated network-related errors detected: {count} events within last 10 minutes.",
            "event_id": None,
            "details": {
                "count": count,
                "threshold": 10,
                "window_minutes": 10,
                "keywords": ["error", "failed", "timeout", "refused"],
            },
            "status": "active",
            "resolved_at": None,
            "resolved_by": None,
            "resolution_notes": None,
        }
    
    @staticmethod
    def create_service_crash(
        detected_at: Optional[dt.datetime] = None,
        count: int = 3,
        severity: str = "high"
    ) -> Dict[str, Any]:
        """Инцидент сбоя службы."""
        return {
            "detected_at": detected_at or dt.datetime.utcnow(),
            "incident_type": "service_crash_or_restart",
            "severity": severity,
            "description": f"Service crash/restart indicators detected: {count} events.",
            "event_id": None,
            "details": {
                "count": count,
                "threshold": 1,
                "keywords": ["crash", "terminated", "panic", "exited", "restart"],
                "service": "nginx",
            },
            "status": "active",
            "resolved_at": None,
            "resolved_by": None,
            "resolution_notes": None,
        }
    
    @staticmethod
    def create_resolved_incident(
        detected_at: Optional[dt.datetime] = None,
        resolved_at: Optional[dt.datetime] = None,
        resolved_by: str = "admin"
    ) -> Dict[str, Any]:
        """Разрешённый инцидент."""
        incident = IncidentFactory.create_multiple_failed_logins(
            detected_at=detected_at,
            severity="high"
        )
        incident["status"] = "resolved"
        incident["resolved_at"] = resolved_at or dt.datetime.utcnow()
        incident["resolved_by"] = resolved_by
        incident["resolution_notes"] = "Проблема устранена. Пароль пользователя сброшен."
        return incident


# =============================================================================
# Фабрика пользователей
# =============================================================================

class UserFactory:
    """Фабрика для создания тестовых пользователей."""
    
    @staticmethod
    def create_admin(
        username: str = "testadmin",
        password: str = "test123",
        full_name: str = "Тестовый Администратор",
        email: str = "admin@test.local",
        phone: str = "+79991234567"
    ) -> Dict[str, Any]:
        """Пользователь с ролью администратора."""
        return {
            "username": username,
            "password": password,
            "role": "admin",
            "full_name": full_name,
            "email": email,
            "phone": phone,
        }
    
    @staticmethod
    def create_operator(
        username: str = "testoperator",
        password: str = "test123",
        full_name: str = "Тестовый Оператор",
        email: str = "operator@test.local",
        phone: str = "+79997654321"
    ) -> Dict[str, Any]:
        """Пользователь с ролью оператора."""
        return {
            "username": username,
            "password": password,
            "role": "operator",
            "full_name": full_name,
            "email": email,
            "phone": phone,
        }
    
    @staticmethod
    def create_employee(
        username: str = "testemployee",
        password: str = "test123",
        full_name: str = "Тестовый Сотрудник",
        email: str = "employee@test.local",
        phone: str = "+79991112233"
    ) -> Dict[str, Any]:
        """Пользователь с ролью сотрудника."""
        return {
            "username": username,
            "password": password,
            "role": "employee",
            "full_name": full_name,
            "email": email,
            "phone": phone,
        }


# =============================================================================
# Фабрика уведомлений
# =============================================================================

class NotificationFactory:
    """Фабрика для создания тестовых уведомлений."""
    
    @staticmethod
    def create_critical_incident_notification(
        incident_id: Optional[int] = None,
        title: str = "Обнаружены множественные неуспешные попытки входа",
        message: str = "Обнаружены множественные неуспешные попытки входа\n\nЧТО ДЕЛАТЬ НЕМЕДЛЕННО:\n1. Сохраните все открытые файлы\n2. Не выключайте компьютер принудительно\n3. Запишите код ошибки (если есть)\n4. ЗВОНИТЕ: +7 (999) 123-45-67\n\n⏰ Не откладывайте!"
    ) -> Dict[str, Any]:
        """Уведомление о критическом инциденте."""
        return {
            "notification_type": "incident",
            "severity": "critical",
            "title": title,
            "message": message,
            "incident_id": incident_id,
            "event_id": None,
            "channel": "telegram",
            "status": "sent",
            "details": {},
        }
    
    @staticmethod
    def create_high_incident_notification(
        incident_id: Optional[int] = None,
        title: str = "Обнаружен сбой или перезапуск службы",
        message: str = "Обнаружен сбой или перезапуск службы nginx\n\nПЛАН ДЕЙСТВИЙ:\n1. Сохраните все файлы\n2. Закройте приложение с ошибками\n3. Перезагрузите компьютер\n4. Если проблема повторилась — звоните: +7 (999) 123-45-67\n\n⏰ Решите в ближайшее время"
    ) -> Dict[str, Any]:
        """Уведомление о высоком инциденте."""
        return {
            "notification_type": "incident",
            "severity": "high",
            "title": title,
            "message": message,
            "incident_id": incident_id,
            "event_id": None,
            "channel": "telegram",
            "status": "sent",
            "details": {},
        }
    
    @staticmethod
    def create_test_notification(
        title: str = "Тестовое уведомление",
        message: str = "Это тестовое уведомление для проверки работы системы."
    ) -> Dict[str, Any]:
        """Простое тестовое уведомление."""
        return {
            "notification_type": "test",
            "severity": "low",
            "title": title,
            "message": message,
            "incident_id": None,
            "event_id": None,
            "channel": "internal",
            "status": "pending",
            "details": {},
        }


# =============================================================================
# Фабрика моков для коллекторов логов
# =============================================================================

class LogCollectorMock:
    """Мок для имитации сборщика логов."""
    
    @staticmethod
    def get_mock_file_lines() -> List[str]:
        """Возвращает тестовые строки лога для имитации чтения из файла."""
        return [
            "2026-02-22 15:00:00,000 ERROR nginx[1234]: Connection timeout to 10.0.0.5:80",
            "2026-02-22 15:00:05,000 ERROR sshd[5678]: Failed login attempt for user admin",
            "2026-02-22 15:00:10,000 CRITICAL zoom[9999]: Application crashed: out of memory",
            "2026-02-22 15:00:15,000 INFO kernel[0]: System startup completed successfully",
            "2026-02-22 15:00:20,000 ERROR nginx[1234]: Connection refused to 10.0.0.5:443",
            "2026-02-22 15:00:25,000 WARNING systemd[1]: nginx.service: Main process exited, status=1/FAILURE",
            "2026-02-22 15:00:30,000 ERROR sshd[5678]: Failed password for user root from 192.168.1.100",
            "2026-02-22 15:00:35,000 ERROR nginx[1234]: Network unreachable to backend-server:8080",
            "2026-02-22 15:00:40,000 CRITICAL launchd[0]: service terminated unexpectedly, restarting",
            "2026-02-22 15:00:45,000 ERROR sshd[5678]: Authentication failure for user admin",
        ]
    
    @staticmethod
    def get_mock_macos_log_entries() -> List[Dict[str, Any]]:
        """Возвращает тестовые записи macOS Unified Log."""
        return [
            {
                "timestamp": "2026-02-22T15:00:00Z",
                "eventMessage": "Connection timeout to 10.0.0.5:80",
                "messageType": "error",
                "processName": "nginx",
                "subsystem": "com.apple.network",
            },
            {
                "timestamp": "2026-02-22T15:00:05Z",
                "eventMessage": "Failed login attempt for user admin",
                "messageType": "error",
                "processName": "sshd",
                "subsystem": "com.apple.security",
            },
            {
                "timestamp": "2026-02-22T15:00:10Z",
                "eventMessage": "Application crashed: out of memory",
                "messageType": "fault",
                "processName": "zoom",
                "subsystem": "com.apple.application",
            },
        ]
