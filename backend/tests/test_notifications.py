import unittest
from unittest.mock import Mock, MagicMock

from siem_backend.services.notifications import get_telegram_advice, incident_text_ru
from siem_backend.services.normalization import EventClassifier
from siem_backend.data.models import Incident


class TestTelegramAdvice(unittest.TestCase):

    def test_critical_advice(self):
        advice = get_telegram_advice("critical")
        self.assertIn("ЧТО ДЕЛАТЬ НЕМЕДЛЕННО", advice)
        self.assertIn("Сохраните все открытые файлы", advice)
        self.assertIn("ЗВОНИТЕ", advice)
        self.assertIn("+7 (999) 123-45-67", advice)
        self.assertIn("⏰ Не откладывайте", advice)

    def test_high_advice(self):
        advice = get_telegram_advice("high")
        self.assertIn("ПЛАН ДЕЙСТВИЙ", advice)
        self.assertIn("Сохраните все файлы", advice)
        self.assertIn("Перезагрузите компьютер", advice)
        self.assertIn("звоните", advice)
        self.assertIn("+7 (999) 123-45-67", advice)

    def test_medium_advice_empty(self):
        advice = get_telegram_advice("medium")
        self.assertEqual(advice, "")

    def test_low_advice_empty(self):
        advice = get_telegram_advice("low")
        self.assertEqual(advice, "")

    def test_unknown_severity(self):
        advice = get_telegram_advice("unknown")
        self.assertEqual(advice, "")


class TestIncidentTextRu(unittest.TestCase):
    """Тесты формирования текста инцидента (нормализованная модель)."""

    def _create_mock_incident(self, incident_type_id: int, severity_id: int, description: str, details: dict):
        """Создаёт мок инцидента с нормализованной структурой."""
        incident = Mock(spec=Incident)
        incident.id = 1
        incident.incident_type_id = incident_type_id
        incident.incident_type_rel = None
        incident.severity_id = severity_id
        incident.severity_rel = None
        incident.description = description
        incident.details = details
        incident.event_id = None
        return incident

    def test_multiple_failed_logins(self):
        db = Mock()
        db.execute.return_value.scalar_one_or_none.return_value = "multiple_failed_logins"
        
        incident = self._create_mock_incident(
            incident_type_id=1,
            severity_id=3,
            description="Test",
            details={"count": 5}
        )
        text = incident_text_ru(incident, db)
        self.assertIn("неуспешные попытки входа", text)

    def test_repeated_network_errors(self):
        db = Mock()
        db.execute.return_value.scalar_one_or_none.return_value = "repeated_network_errors"
        
        incident = self._create_mock_incident(
            incident_type_id=2,
            severity_id=3,
            description="Test",
            details={"events_count": 15, "window_minutes": 10}
        )
        text = incident_text_ru(incident, db)
        self.assertIn("повторяющиеся сетевые ошибки", text)
        self.assertIn("15", text)
        self.assertIn("10", text)

    def test_service_crash_with_name(self):
        db = Mock()
        db.execute.return_value.scalar_one_or_none.return_value = "service_crash_or_restart"
        
        incident = self._create_mock_incident(
            incident_type_id=3,
            severity_id=4,
            description="Test",
            details={"service": "nginx"}
        )
        text = incident_text_ru(incident, db)
        self.assertIn("сбой или перезапуск службы", text)
        self.assertIn("nginx", text)

    def test_service_crash_without_name(self):
        db = Mock()
        db.execute.return_value.scalar_one_or_none.return_value = "service_crash_or_restart"
        
        incident = self._create_mock_incident(
            incident_type_id=3,
            severity_id=4,
            description="Test",
            details={}
        )
        text = incident_text_ru(incident, db)
        self.assertIn("сбой или перезапуск службы", text)
        self.assertNotIn("nginx", text)


class TestEventClassifier(unittest.TestCase):

    def test_auth_keywords(self):
        test_cases = [
            "Failed password for user admin",
            "Authentication failure",
            "Invalid password",
            "Login failed",
            "Unauthorized access",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "authentication")

    def test_network_keywords(self):
        test_cases = [
            "Connection timeout to 10.0.0.5",
            "DNS resolution failed",
            "Socket connection refused",
            "Network unreachable",
            "TCP handshake timeout",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "network")

    def test_service_keywords(self):
        test_cases = [
            "nginx.service crashed",
            "systemd: Service restart",
            "Daemon terminated",
            "Launchd: exited",
            "Kernel panic",
        ]
        
        for message in test_cases:
            with self.subTest(message=message):
                event_type = EventClassifier.classify_event_type(message, {})
                self.assertEqual(event_type, "service")

    def test_source_category_service(self):
        test_cases = [
            ("systemd[1]: nginx.service crashed", {"process": "systemd"}),
            ("launchd: Service exited", {"process": "launchd"}),
            ("Service nginx failed to start", {}),
        ]
        
        for message, raw_data in test_cases:
            with self.subTest(message=message):
                category = EventClassifier.classify_source_category(message, raw_data, "linux")
                self.assertEqual(category, "service")

    def test_source_category_user_process(self):
        test_cases = [
            ("nginx.service: Main process exited", {"process": "nginx"}),
            ("Application crashed", {"application": "zoom"}),
            ("User process terminated", {}),
        ]
        
        for message, raw_data in test_cases:
            with self.subTest(message=message):
                category = EventClassifier.classify_source_category(message, raw_data, "linux")
                self.assertEqual(category, "user_process")


if __name__ == "__main__":
    unittest.main()
