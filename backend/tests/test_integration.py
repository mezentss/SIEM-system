"""
Интеграционные тесты с использованием моков.

Тестируют полный цикл работы системы:
1. Сбор логов (мок)
2. Нормализация событий
3. Сохранение в БД
4. Анализ и формирование инцидентов
5. Уведомления

Запуск:
    python -m pytest tests/test_integration.py -v
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch

from tests.mocks import (
    EventFactory,
    IncidentFactory,
    UserFactory,
    NotificationFactory,
    LogCollectorMock,
)
from siem_backend.services.normalization import EventClassifier, NormalizedEvent
from siem_backend.services.analysis.rules.failed_logins import MultipleFailedLoginsRule
from siem_backend.services.analysis.rules.network_errors import RepeatedNetworkErrorsRule
from siem_backend.services.analysis.rules.service_crash import ServiceCrashOrRestartRule
from siem_backend.data.models import Event


class TestEventNormalization(unittest.TestCase):
    """Тесты нормализации событий."""

    def test_auth_event_classification(self):
        """Классификация события аутентификации."""
        message = "Failed login attempt for user admin"
        raw_data = {"process": "sshd"}
        
        event_type = EventClassifier.classify_event_type(message, raw_data)
        source_category = EventClassifier.classify_source_category(message, raw_data, "macos")
        
        self.assertEqual(event_type, "authentication")
        self.assertIn(source_category, ["auth", "service"])

    def test_network_event_classification(self):
        """Классификация сетевого события."""
        message = "Connection timeout to 10.0.0.5:80"
        raw_data = {"process": "nginx"}
        
        event_type = EventClassifier.classify_event_type(message, raw_data)
        
        self.assertEqual(event_type, "network")

    def test_service_event_classification(self):
        """Классификация события службы."""
        message = "nginx.service: Main process exited, status=1/FAILURE"
        raw_data = {"process": "systemd"}
        
        event_type = EventClassifier.classify_event_type(message, raw_data)
        
        self.assertEqual(event_type, "service")

    def test_process_event_classification(self):
        """Классификация события приложения."""
        message = "Zoom memory allocation for video buffer failed"
        raw_data = {"process": "zoom", "application": "zoom"}
        
        event_type = EventClassifier.classify_event_type(message, raw_data)
        
        self.assertEqual(event_type, "process")


class TestMockEvents(unittest.TestCase):
    """Тесты с использованием фабрики моков событий."""

    def test_create_auth_failed_event(self):
        """Создание мока события неудачной попытки входа."""
        event = EventFactory.create_auth_failed()
        
        self.assertEqual(event["event_type"], "authentication")
        self.assertEqual(event["severity"], "high")
        self.assertIn("Failed login", event["message"])

    def test_create_network_error_event(self):
        """Создание мока события сетевой ошибки."""
        event = EventFactory.create_network_error()
        
        self.assertEqual(event["event_type"], "network")
        self.assertIn("timeout", event["message"])

    def test_create_service_crash_event(self):
        """Создание мока события сбоя службы."""
        event = EventFactory.create_service_crash()
        
        self.assertEqual(event["event_type"], "service")
        self.assertIn("FAILURE", event["message"])

    def test_create_batch_auth_failed(self):
        """Создание пакета событий неудачных попыток входа."""
        events = EventFactory.create_batch_auth_failed(count=10)
        
        self.assertEqual(len(events), 10)
        for event in events:
            self.assertEqual(event["event_type"], "authentication")
            self.assertIn("Failed login", event["message"])

    def test_create_batch_network_errors(self):
        """Создание пакета событий сетевых ошибок."""
        events = EventFactory.create_batch_network_errors(count=15)
        
        self.assertEqual(len(events), 15)
        for event in events:
            self.assertEqual(event["event_type"], "network")


class TestMockIncidents(unittest.TestCase):
    """Тесты с использованием фабрики моков инцидентов."""

    def test_create_multiple_failed_logins_incident(self):
        """Создание мока инцидента множественных попыток входа."""
        incident = IncidentFactory.create_multiple_failed_logins(count=10)
        
        self.assertEqual(incident["incident_type"], "multiple_failed_logins")
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(incident["details"]["count"], 10)

    def test_create_network_errors_incident(self):
        """Создание мока инцидента сетевых ошибок."""
        incident = IncidentFactory.create_network_errors(count=15)
        
        self.assertEqual(incident["incident_type"], "repeated_network_errors")
        self.assertEqual(incident["severity"], "medium")

    def test_create_service_crash_incident(self):
        """Создание мока инцидента сбоя службы."""
        incident = IncidentFactory.create_service_crash(count=3)
        
        self.assertEqual(incident["incident_type"], "service_crash_or_restart")
        self.assertIn("nginx", incident["details"]["service"])

    def test_create_resolved_incident(self):
        """Создание мока разрешённого инцидента."""
        incident = IncidentFactory.create_resolved_incident()
        
        self.assertEqual(incident["status"], "resolved")
        self.assertIsNotNone(incident["resolved_at"])
        self.assertEqual(incident["resolved_by"], "admin")


class TestMockUsers(unittest.TestCase):
    """Тесты с использованием фабрики моков пользователей."""

    def test_create_admin_user(self):
        """Создание мока пользователя-администратора."""
        user = UserFactory.create_admin()
        
        self.assertEqual(user["role"], "admin")
        self.assertEqual(user["username"], "testadmin")

    def test_create_operator_user(self):
        """Создание мока пользователя-оператора."""
        user = UserFactory.create_operator()
        
        self.assertEqual(user["role"], "operator")
        self.assertEqual(user["username"], "testoperator")

    def test_create_employee_user(self):
        """Создание мока пользователя-сотрудника."""
        user = UserFactory.create_employee()
        
        self.assertEqual(user["role"], "employee")
        self.assertEqual(user["username"], "testemployee")


class TestMockNotifications(unittest.TestCase):
    """Тесты с использованием фабрики моков уведомлений."""

    def test_create_critical_notification(self):
        """Создание мока уведомления о критическом инциденте."""
        notification = NotificationFactory.create_critical_incident_notification()
        
        self.assertEqual(notification["severity"], "critical")
        self.assertEqual(notification["channel"], "telegram")
        self.assertEqual(notification["status"], "sent")
        self.assertIn("ЗВОНИТЕ", notification["message"])

    def test_create_high_notification(self):
        """Создание мока уведомления о высоком инциденте."""
        notification = NotificationFactory.create_high_incident_notification()
        
        self.assertEqual(notification["severity"], "high")
        self.assertIn("Перезагрузите", notification["message"])

    def test_create_test_notification(self):
        """Создание простого тестового уведомления."""
        notification = NotificationFactory.create_test_notification()
        
        self.assertEqual(notification["severity"], "low")
        self.assertEqual(notification["channel"], "internal")
        self.assertEqual(notification["status"], "pending")


class TestLogCollectorMock(unittest.TestCase):
    """Тесты мока сборщика логов."""

    def test_get_mock_file_lines(self):
        """Получение тестовых строк лога."""
        lines = LogCollectorMock.get_mock_file_lines()
        
        self.assertEqual(len(lines), 10)
        self.assertIn("ERROR", lines[0])
        self.assertIn("Failed login", lines[1])
        self.assertIn("crashed", lines[2])

    def test_get_mock_macos_log_entries(self):
        """Получение тестовых записей macOS Unified Log."""
        entries = LogCollectorMock.get_mock_macos_log_entries()
        
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["processName"], "nginx")
        self.assertEqual(entries[1]["messageType"], "error")
        self.assertEqual(entries[2]["messageType"], "fault")


class TestAnalysisRulesWithMocks(unittest.TestCase):
    """Тесты правил анализа с использованием моков."""

    def setUp(self):
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()

    def test_multiple_failed_logins_rule_with_mock_events(self):
        """Правило множественных попыток входа с моками событий."""
        # Создаём моки объектов Event
        mock_events = []
        for i in range(10):
            mock_events.append(Event(
                id=i+1,
                ts=datetime.utcnow(),
                source_os_id=1,
                source_category_id=1,
                event_type_id=1,
                severity_id=3,
                message="Failed login attempt for user admin",
                raw_data={"process": "sshd", "user": "admin"},
            ))
        
        # Мокаем запрос к БД
        self.db.execute.return_value.scalars.return_value.all.return_value = mock_events
        
        # Запускаем правило
        rule = MultipleFailedLoginsRule(threshold=5, window_minutes=10)
        candidates = rule.run(self.db, since=self.since, until=self.until)
        
        # Проверяем результат
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "multiple_failed_logins")
        self.assertIn(candidates[0].severity, ["warning", "critical"])

    def test_network_errors_rule_with_mock_events(self):
        """Правило сетевых ошибок с моками событий."""
        # Создаём моки объектов Event
        mock_events = []
        for i in range(15):
            mock_events.append(Event(
                id=i+1,
                ts=datetime.utcnow(),
                source_os_id=1,
                source_category_id=1,
                event_type_id=1,
                severity_id=2,
                message=f"Connection timeout to backend-server-{i}:8080",
                raw_data={"process": "nginx"},
            ))
        
        # Мокаем запрос к БД
        self.db.execute.return_value.scalars.return_value.all.return_value = mock_events
        
        # Запускаем правило
        rule = RepeatedNetworkErrorsRule(threshold=10, window_minutes=10)
        candidates = rule.run(self.db, since=self.since, until=self.until)
        
        # Проверяем результат
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "repeated_network_errors")

    def test_service_crash_rule_with_mock_events(self):
        """Правило сбоев служб с моками событий."""
        # Создаём моки объектов Event
        mock_events = []
        for i in range(5):
            mock_events.append(Event(
                id=i+1,
                ts=datetime.utcnow(),
                source_os_id=1,
                source_category_id=1,
                event_type_id=1,
                severity_id=3,
                message=f"nginx.service: Main process exited, status=1/FAILURE (attempt {i+1})",
                raw_data={"process": "nginx", "service": "nginx.service"},
            ))
        
        # Мокаем запрос к БД
        self.db.execute.return_value.scalars.return_value.all.return_value = mock_events
        
        # Запускаем правило
        rule = ServiceCrashOrRestartRule(threshold=1)
        candidates = rule.run(self.db, since=self.since, until=self.until)
        
        # Проверяем результат
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "service_crash_or_restart")


class TestFullWorkflowWithMocks(unittest.TestCase):
    """Тесты полного цикла работы системы с моками."""

    def test_auth_attack_workflow(self):
        """Полный цикл: атака на учётные данные → обнаружение → инцидент."""
        # 1. Создаём пакет событий неудачных попыток входа
        auth_events = EventFactory.create_batch_auth_failed(count=10)
        
        # 2. Проверяем классификацию
        for event in auth_events:
            event_type = EventClassifier.classify_event_type(event["message"], event["raw_data"])
            self.assertEqual(event_type, "authentication")
        
        # 3. Создаём инцидент
        incident = IncidentFactory.create_multiple_failed_logins(count=10)
        self.assertEqual(incident["incident_type"], "multiple_failed_logins")
        self.assertEqual(incident["severity"], "critical")
        
        # 4. Создаём уведомление
        notification = NotificationFactory.create_critical_incident_notification(
            incident_id=incident.get("id")
        )
        self.assertEqual(notification["severity"], "critical")
        self.assertEqual(notification["channel"], "telegram")
        self.assertIn("ЗВОНИТЕ", notification["message"])

    def test_network_failure_workflow(self):
        """Полный цикл: сетевые сбои → обнаружение → инцидент."""
        # 1. Создаём пакет событий сетевых ошибок
        network_events = EventFactory.create_batch_network_errors(count=15)
        
        # 2. Проверяем классификацию
        for event in network_events:
            event_type = EventClassifier.classify_event_type(event["message"], event["raw_data"])
            self.assertEqual(event_type, "network")
        
        # 3. Создаём инцидент
        incident = IncidentFactory.create_network_errors(count=15)
        self.assertEqual(incident["incident_type"], "repeated_network_errors")
        
        # 4. Создаём уведомление
        notification = NotificationFactory.create_high_incident_notification(
            incident_id=incident.get("id")
        )
        self.assertEqual(notification["severity"], "high")

    def test_service_crash_workflow(self):
        """Полный цикл: сбой службы → обнаружение → инцидент."""
        # 1. Создаём пакет событий сбоев служб
        service_events = EventFactory.create_batch_service_crashes(count=5)
        
        # 2. Проверяем классификацию
        for event in service_events:
            event_type = EventClassifier.classify_event_type(event["message"], event["raw_data"])
            self.assertEqual(event_type, "service")
        
        # 3. Создаём инцидент
        incident = IncidentFactory.create_service_crash(count=5)
        self.assertEqual(incident["incident_type"], "service_crash_or_restart")


if __name__ == "__main__":
    unittest.main()
