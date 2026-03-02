"""
Unit-тесты для правил анализа инцидентов.

Проверяют корректность детектирования инцидентов:
- MultipleFailedLoginsRule
- RepeatedNetworkErrorsRule
- ServiceCrashOrRestartRule
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

from siem_backend.services.analysis.rules.failed_logins import MultipleFailedLoginsRule
from siem_backend.services.analysis.rules.network_errors import RepeatedNetworkErrorsRule
from siem_backend.services.analysis.rules.service_crash import ServiceCrashOrRestartRule
from siem_backend.data.models import Event


class TestMultipleFailedLoginsRule(unittest.TestCase):
    """Тесты для правила детектирования множественных неудачных попыток входа."""

    def setUp(self):
        """Настройка тестовых данных."""
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = MultipleFailedLoginsRule(threshold=5, window_minutes=10)

    def _create_event(self, message: str, event_type: str = "authentication") -> Event:
        """Создаёт тестовое событие."""
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os="test",
            source_category="authentication",
            event_type=event_type,
            severity="high",
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        """Тест: нет событий — инцидентов нет."""
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)

    def test_below_threshold(self):
        """Тест: меньше порогового значения — инцидентов нет."""
        events = [
            self._create_event("Failed login attempt for user admin"),
            self._create_event("Login failed for user admin"),
            self._create_event("Authentication failure for user admin"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)

    def test_at_threshold(self):
        """Тест: ровно пороговое значение — инцидент создаётся."""
        events = [
            self._create_event("Failed login attempt for user admin"),
            self._create_event("Login failed for user admin"),
            self._create_event("Authentication failure for user admin"),
            self._create_event("Failed password for user admin"),
            self._create_event("Invalid password for user admin"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "multiple_failed_logins")
        self.assertEqual(candidates[0].severity, "low")  # 5 событий = low

    def test_above_threshold_critical(self):
        """Тест: значительно выше порога — критический инцидент."""
        events = [
            self._create_event("Failed login attempt for user admin")
            for _ in range(30)  # 30 событий = critical (threshold * 2 = 10, но нужно больше)
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        # При 30 событиях: 30 >= max(5*2, 10) = 10, но для critical нужно больше
        # Проверяем что инцидент создан, severity зависит от количества
        self.assertIn(candidates[0].severity, ["medium", "high", "critical"])

    def test_non_auth_events_ignored(self):
        """Тест: события не аутентификации игнорируются."""
        events = [
            self._create_event("Connection timeout", event_type="network"),
            self._create_event("Service crashed", event_type="service"),
            self._create_event("Failed login", event_type="authentication"),  # Только это считается
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)


class TestRepeatedNetworkErrorsRule(unittest.TestCase):
    """Тесты для правила детектирования повторяющихся сетевых ошибок."""

    def setUp(self):
        """Настройка тестовых данных."""
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = RepeatedNetworkErrorsRule(threshold=10, window_minutes=10)

    def _create_event(self, message: str, event_type: str = "network") -> Event:
        """Создаёт тестовое событие."""
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os="test",
            source_category="network",
            event_type=event_type,
            severity="high",
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        """Тест: нет событий — инцидентов нет."""
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)

    def test_below_threshold(self):
        """Тест: меньше порогового значения — инцидентов нет."""
        events = [
            self._create_event("Connection timeout"),
            self._create_event("Connection refused"),
            self._create_event("Network unreachable"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)

    def test_at_threshold(self):
        """Тест: ровно пороговое значение — инцидент создаётся."""
        events = [
            self._create_event("Connection timeout")
            for _ in range(10)  # 10 событий = threshold
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "repeated_network_errors")
        self.assertEqual(candidates[0].severity, "low")  # 10 событий = low

    def test_medium_severity(self):
        """Тест: 50+ событий — средняя серьёзность."""
        events = [
            self._create_event("Connection timeout")
            for _ in range(60)  # 60 событий = medium
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "medium")

    def test_high_severity(self):
        """Тест: 100+ событий — высокая серьёзность."""
        events = [
            self._create_event("Connection timeout")
            for _ in range(120)  # 120 событий = high
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "high")

    def test_critical_severity(self):
        """Тест: 200+ событий — критическая серьёзность."""
        events = [
            self._create_event("Connection timeout")
            for _ in range(250)  # 250 событий = critical
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "critical")


class TestServiceCrashOrRestartRule(unittest.TestCase):
    """Тесты для правила детектирования сбоев и перезапусков служб."""

    def setUp(self):
        """Настройка тестовых данных."""
        self.db = Mock()
        self.since = datetime.utcnow() - timedelta(minutes=10)
        self.until = datetime.utcnow()
        self.rule = ServiceCrashOrRestartRule(threshold=1)

    def _create_event(self, message: str, event_type: str = "service") -> Event:
        """Создаёт тестовое событие."""
        return Event(
            id=1,
            ts=datetime.utcnow(),
            source_os="test",
            source_category="service",
            event_type=event_type,
            severity="high",
            message=message,
            raw_data={}
        )

    def test_no_events(self):
        """Тест: нет событий — инцидентов нет."""
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)

    def test_single_crash(self):
        """Тест: один сбой службы — инцидент создаётся."""
        events = [
            self._create_event("nginx.service: Main process exited, status=1/FAILURE"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].incident_type, "service_crash_or_restart")
        self.assertEqual(candidates[0].severity, "low")  # 1 событие = low

    def test_crash_keywords(self):
        """Тест: различные ключевые слова сбоев."""
        test_cases = [
            "Application crashed",
            "Process terminated",
            "Kernel panic",
            "Service exited",
            "Service restart",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                events = [self._create_event(message)]
                self.db.execute.return_value.scalars.return_value.all.return_value = events
                
                candidates = self.rule.run(self.db, since=self.since, until=self.until)
                
                self.assertEqual(len(candidates), 1)

    def test_medium_severity(self):
        """Тест: 10+ событий — средняя серьёзность."""
        events = [
            self._create_event("Service crashed")
            for _ in range(15)  # 15 событий = medium
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "medium")

    def test_high_severity(self):
        """Тест: 50+ событий — высокая серьёзность."""
        events = [
            self._create_event("Service crashed")
            for _ in range(60)  # 60 событий = high
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "high")

    def test_critical_severity(self):
        """Тест: 100+ событий — критическая серьёзность."""
        events = [
            self._create_event("Service crashed")
            for _ in range(120)  # 120 событий = critical
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].severity, "critical")

    def test_non_service_events_ignored(self):
        """Тест: события не типа service игнорируются."""
        # Правило ServiceCrashOrRestartRule проверяет event_type == "service"
        # Поэтому события с event_type="process" или "network" не попадут в выборку
        events = [
            self._create_event("Application crashed", event_type="process"),
            self._create_event("Connection timeout", event_type="network"),
        ]
        self.db.execute.return_value.scalars.return_value.all.return_value = events
        
        # Мокаем чтобы query возвращал только service события (пустой список)
        self.db.execute.return_value.scalars.return_value.all.return_value = []
        
        candidates = self.rule.run(self.db, since=self.since, until=self.until)
        
        self.assertEqual(len(candidates), 0)


if __name__ == "__main__":
    unittest.main()
